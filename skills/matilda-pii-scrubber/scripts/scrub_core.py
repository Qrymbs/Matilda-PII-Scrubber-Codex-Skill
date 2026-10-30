"""Human-PII-only policy; unknown data, infrastructure IDs and machine secrets remain.
Masking requires positive human evidence. Contextual review handles ambiguous names.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from dataclasses import dataclass, field as dataclass_field
from datetime import date, datetime, time
from decimal import Decimal, InvalidOperation
import html
import json
import re
from urllib.parse import unquote
from typing import Any

class ScrubError(Exception):
    def __init__(self, code):
        self.code = code if re.fullmatch(r"[a-z][a-z0-9_]{0,79}", code) else "processing_failed"
        super().__init__(self.code)

NUMERIC_FIELDS = set("""cost amount price rate quantity usage usageamount usagequantity consumedquantity unblendedcost blendedcost amortizedcost effectivecost netcost pretaxcost billedcost listcost listcosts contractedcost pricingquantity pricingquantitys pricingquantities costinbillingcurrency costinusd unitprice retailprice effectiveprice discount tax credits savings subtotal percentchange percentagechange cpu cpus vcpu vcpus ocpu ocpus memory memorygb memorygib memorymb capacity capacitygb storage storagegb cores cpucount count hours minutes seconds duration utilization cpupercent memorypercent""".split())
CATALOG_ID_FIELDS = {"skuid","skupriceid","serviceid","meterid","rateid","priceid","productid","offerid"}
BILLING_DATE_FIELDS = set("""billingperiodstart billingperiodend billingperiodstartdate billingperiodenddate chargeperiodstart chargeperiodend usagestart usageend usagestartdate usageenddate invoicemonth billingmonth collectiontimestamp collectiontime collectiondate""".split())
_GROUPS = {
"human_names": set("""firstname lastname middlename fullname givenname familyname surname preferredname maidenname personname personalname contactname contactperson employeename studentname patientname beneficiaryname emergencycontactname cardholdername ownername author creator lastmodifiedby refreshedby preparedby approvedby personinitials humaninitials""".split()),
"human_email_addresses": set("""email emailaddress personalemail personalemailaddress workemail employeeemail contactemail contactemailaddress useremail userprincipalname upn""".split()),
"human_phone_numbers": set("""phone phonenumber telephone telephonenumber mobilephone mobilephonenumber cellphone contactphone personalphone homephone workphone fax faxnumber""".split()),
"human_government_identifiers": set("""ssn socialsecuritynumber passport passportnumber driverslicense driverslicensenumber driverlicensenumber nationalid nationalidentificationnumber individualtaxid itin""".split()),
"human_employee_student_patient_identifiers": set("""employeeid employeenumber studentid studentnumber patientid medicalrecordnumber personid personnelnumber beneficiaryid healthplanbeneficiarynumber""".split()),
"human_usernames": set("""username userlogin loginname personusername personalusername employeeusername contactusername samaccountname""".split()),
"human_home_addresses": set("""homeaddress residentialaddress personaladdress personalmailingaddress employeeaddress patientaddress studentaddress""".split()),
"human_birth_dates": set("""dateofbirth birthdate dob birthday placeofbirth birthplace dateofdeath""".split()),
"human_personal_financial_data": set("""salary annualsalary employeesalary personalincome personalbankaccount personalbankaccountnumber employeebankaccount personalcreditcard personalcreditcardnumber""".split()),
"human_sensitive_personal_data": set("""sexualorientation religiousbelief religiousbeliefs politicalopinion politicalopinions patientdiagnosis medicaldiagnosis persondisability personalmedicalhistory geneticprofile""".split()),
"human_personal_credentials": set("""personalpassword employeepassword personpassword userpassword personalpin personalsecurityanswer personalrecoverycode""".split()),
}
_PERSON_CONTAINERS = set("""person personal personaldetails contact contactperson employee patient student beneficiary emergencycontact user owner author""".split())
_PROSE_FIELDS = set("""description servicedescription skudescription comment comments note notes text freetext content message summary detail details annotation annotations""".split())
_ALL_POLICY_FIELDS = set().union(*_GROUPS.values(), _PERSON_CONTAINERS, _PROSE_FIELDS, NUMERIC_FIELDS, CATALOG_ID_FIELDS, BILLING_DATE_FIELDS)
_INFRA_FIELDS = set("""id account accountid payeraccountid usageaccountid linkedaccountid subscriptionid tenantid tenancyid projectid resourceid resourcearn arn ocid hostname hostid vm vmid vmname instanceid databaseid diskid networkid subnetid principal principalid machineprincipal serviceprincipal objectid skuid serviceid meterid serialnumber uuid guid ip ipaddress mac macaddress domain path resourcepath""".split())
_ALL_POLICY_FIELDS |= _INFRA_FIELDS
_EMPTY_MARKERS = {"","unknown","none","null","n/a","na","not applicable","not available","redacted","[redacted]","-"}
_MACHINE_WORDS = set("""root admin administrator system localservice networkservice anonymous guest ubuntu oracle ec2-user centos debian postgres mysql www-data apache nginx nobody daemon service default customer tenant user users app apps data billing support helpdesk operations platform engineering finops shared""".split())
_MACHINE_WORDS |= {"python-docx", "openpyxl", "pandas", "python", "codex", "excel", "microsoft excel", "libreoffice", "apache poi", "serviceprincipal", "superuser"}
_MACHINE_WORDS |= {"microsoft word", "microsoft office", "microsoft office user", "reportlab pdf library", "python software foundation"}
_SHARED_MAILBOXES = _MACHINE_WORDS | set("""info sales accounts accounting finance security abuse alerts alert monitor monitoring notifications notification noreply no-reply donotreply do-not-reply postmaster webmaster devops it hr contact hello team serviceaccount automation""".split())
_SERVICE_WORDS=set("""account accounts accounting administrator administration admin alert alerts analytics api app application applications automation billing bot build builder certificate certificates ci cicd cloud commercial compliance contact cost customer data database deployment deploy dev developer developers development devops engineering etl fabric finance finops forecast forecasting group helpdesk hr iam identity ingestion infrastructure integration it job legal leads lens mail mailbox manufacturing market metrics migration migrate monitor monitoring notification notifications operation operations ops orchestration pipeline platform portal predictive procurement production project quality queue refresh release report reporting robot role sales scheduler security segment service services shared software spin spinoff storage subscription support system tax team terraform test testing tools training warehouse workload""".split())
_TECHNICAL_NAME_WORDS=_SERVICE_WORDS | set("""assigned bit bitness cache capacity cdk cloudformation company corporation corp concurrency cpu department disk division duration ephemeral function gb gib gitlab github gmbh gpu inc incorporated invocation jenkins limited linux llc ltd manager measured memory microsoft month network operating period plc provisioned provisioning ram request restore runner session snapshot tf ubuntu version weighted windows""".split())
_PROFILE_MACHINE_NAMES=_MACHINE_WORDS | {"public","shared","default user","all users","defaultuser0","defaultaccount"}
_SAFE_CODE=re.compile(r"[a-z][a-z0-9_]{0,79}")
_SAFE_LOCATION=re.compile(r"(?:filename|r\d+|c\d+|s\d+|i\d+|k\d+|p\d+|b\d+|l\d+|root|footer)(?:[./](?:r\d+|c\d+|s\d+|i\d+|k\d+|p\d+|b\d+|l\d+))*")
REVIEW_REASON_CODES=frozenset({"ambiguous_email_identity","ambiguous_person_name","ambiguous_person_identifier","ambiguous_actor_identity","ambiguous_person_profile_path","encoded_contact_marker","unparsed_contact_marker","ambiguous_person_container","embedded_person_context_uninspected"})
REVIEW_REASON_CODES=REVIEW_REASON_CODES | {'protected_identifier_contains_pii','protected_identifier_review','schema_label_contains_pii','type_masking_conflict','pii_span_unresolved','formula_pii_requires_review','unsupported_content_uninspected'}
DECISION_REASON_CODES=REVIEW_REASON_CODES | {"context_confirmed_human","context_confirmed_nonpersonal","corroborated_person_profile","manual_context_decision","named_person_email","explicit_person_name","explicit_person_identifier","human_author_metadata","corroborated_personal_path","personal_contact_record","personal_sensitive_record","shared_organizational_mailbox","machine_identity","organization_or_project_label","technical_description","billing_or_infrastructure_value"}

def normalize_field(field):
    if not isinstance(field,str):
        return ""
    text=re.sub(r"([a-z0-9])([A-Z])",r"\1 \2",field)
    text=re.sub(r"[^a-z0-9]+"," ",text.lower()).strip()
    if text.replace(" ","") in _ALL_POLICY_FIELDS:
        return text
    for prefix in ("line item ","lineitem ","product ","pricing ","bill ","reservation ","savings plan ","savingsplan "):
        if text.startswith(prefix):
            return text[len(prefix):]
    return text

def _canonical(field):
    return normalize_field(field).replace(" ","")

def _policy_canonical(field):
    raw=str(field or "")
    if re.search(r"[/.:]",raw) or re.match(r"^(?:user|resource_tags?|tags?)[_ -]",raw,re.I):
        tail=re.split(r"[/.:]",raw)[-1]
        tail=re.sub(r"^(?:resource[_ -]?tags?|tags?|user)[_ -]+","",tail,flags=re.I)
        canonical=_canonical(tail)
        if canonical in {"name","user","username","displayname"}:return "maplabel"
        if canonical in _ALL_POLICY_FIELDS:return canonical
    return _canonical(field)

def classify_field(field):
    name=_policy_canonical(field)
    for category,fields in _GROUPS.items():
        if name in fields:
            return category
    if name in _PERSON_CONTAINERS:
        return "personal_container"
    if name in _PROSE_FIELDS:
        return "free_text"
    if name in NUMERIC_FIELDS:
        return "safe_numeric"
    if name in BILLING_DATE_FIELDS:
        return "safe_billing_date"
    return "preserve"

def is_identifier_field(field):
    return classify_field(field).startswith("human_")

def _has_content(value):
    return value is not None and not (isinstance(value,str) and value.strip().casefold() in _EMPTY_MARKERS)

def _machine_identity(value):
    text=value.strip().strip("'\"").casefold()
    local=text.rsplit("\\",1)[-1].split("@",1)[0]
    if local in _MACHINE_WORDS:
        return True
    if re.search(r"(?:bot|serviceaccount|serviceprincipal|automation)$", local):
        return True
    if re.search(r"(?:^|[._\-/ ])(?:svc|service|serviceaccount|service-account|bot|robot|automation|automated|system|team|shared|group|pipeline|build|deploy|monitor|alerts?)(?:$|[._\-/ 0-9])",local):
        return True
    return bool(re.fullmatch(r"[0-9a-f]{8}-[0-9a-f-]{27,}",local)) or text.startswith(("arn:","ocid1.","http://","https://","/"))

def _human_name(value,strong=False):
    if not isinstance(value,str) or not _has_content(value):
        return False
    text=value.strip().strip("'\"")
    if len(text)>120 or _machine_identity(text):
        return False
    text=re.sub(r"^(?:mr|mrs|ms|miss|dr|prof)\.?\s+","",text,flags=re.I)
    words=text.split()
    if not strong and any(word.casefold().rstrip(".,") in _TECHNICAL_NAME_WORDS | {"company","corporation","corp","inc","incorporated","llc","ltd","limited","plc","gmbh","department","division"} for word in words):
        return False
    return 1<=len(words)<=6 and all(re.fullmatch(r"[^\W\d_]+(?:[.'’\-][^\W\d_]+)*\.?",word,re.UNICODE) for word in words)

_EMAIL_RE=re.compile(r"(?<![\w.!#$%&'*+=?^`{|}~-])([\w.!#$%&'*+=?^`{|}~-]{1,64})@([A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\.[A-Za-z]{2,63})(?![A-Za-z0-9])",re.UNICODE)

def _identity_words(value):
    separated=re.sub(r"([a-z])([A-Z])",r"\1 \2",value)
    separated=re.sub(r"([A-Z]+)([A-Z][a-z])",r"\1 \2",separated)
    return [word.casefold() for word in re.findall(r"[^\W\d_]+|\d+",separated,re.UNICODE)]

def _named_local(local):
    """A name-shaped address, never a dictionary of customer identities."""
    base=local.split("+",1)[0]
    parts=re.split(r"[._-]",base)
    if len(parts)==1:
        words=_identity_words(re.sub(r"\d+$","",base))
        if len(words)!=2 or not re.search(r"[a-z][A-Z]",base):
            return False
    else:
        words=[re.sub(r"\d+$","",word).casefold() for word in parts]
    role_modifiers={"admin","support","team","devops","ops","role"}
    if len(words)>2 and all(word in role_modifiers for word in words[2:]) and not set(words[:2])&_SERVICE_WORDS:
        words=words[:2]
    elif len(words)>2 and all(word in role_modifiers for word in words[:-2]) and not set(words[-2:])&_SERVICE_WORDS:
        words=words[-2:]
    if not (len(words)==2 or len(words)==3 and len(words[1])==1):
        return False
    return all(word.isalpha() for word in words) and len(words[0])>=2 and len(words[-1])>=2 and not (set(words)&(_SERVICE_WORDS | {"health","office","department","division","corporate"}))

def _email_assessment(local,domain,field=None):
    base=local.split("+",1)[0]
    lower=base.casefold();domain=domain.casefold()
    if lower in _SHARED_MAILBOXES and "+" in local and _named_local(local.split("+",1)[1]):return "review"
    if domain.endswith(".gserviceaccount.com") or lower in _SHARED_MAILBOXES or re.match(r"^(?:svc|serviceaccount|serviceprincipal|robot|bot|automation)[._-]",lower):
        return "nonpersonal"
    if _named_local(base):
        return "human"
    words=_identity_words(base)
    functional=[word for word in words if word in _SERVICE_WORDS]
    if functional and (len(functional)>=2 or all(word in _SERVICE_WORDS or word.isdigit() for word in words)):
        return "nonpersonal"
    # Explicit personal fields can identify an opaque personal mailbox; generic
    # Email/Contact and resource identity slots do not prove who owns an alias.
    if _policy_canonical(field) in {"personalemail","personalemailaddress","employeeemail","personemail","personemailaddress"}:
        return "human"
    return "review"

def _personal_email(local,domain):
    return _email_assessment(local,domain)=="human"

def _assessment_text(value):
    """Decode address markers only for assessment; retained content is exact."""
    text=value
    for _ in range(4):
        decoded=html.unescape(unquote(text))
        decoded=re.sub(r"\\u(?:0040|002[eE])",lambda m:"@" if m.group(0)[-2:]=="40" else ".",decoded)
        decoded=re.sub(r"\\x(?:40|2[eE])",lambda m:"@" if m.group(0)[-2:]=="40" else ".",decoded)
        if decoded==text:break
        text=decoded
    return text

def _semantic_person_slot(field):
    text=normalize_field(field)
    suffix=re.split(r"[/.:]",str(field or ""))[-1]
    suffix=re.sub(r"^(?:resource[_ -]?tags?|tags?|user)[_ -]+","",suffix,flags=re.I)
    canonical=_canonical(suffix)
    if canonical in {"owner","contact","creator","createdby","appowner","billingowner","resourcecreator","awscreatedby"}:
        return canonical
    return _canonical(field) if _canonical(field) in {"owner","contact","user","name"} else ""

def requires_context_assessment(field):
    """Adapters must not regex-prefilter away bare person-slot candidates."""
    return classify_field(field).startswith("human_") or classify_field(field)=="personal_container" or bool(_semantic_person_slot(field)) or _policy_canonical(field) in {"personprofile","personalprofilepath","corroboratedpersonprofile"}

def _technical_person_candidate(value):
    words=_identity_words(value)
    return bool(words) and (any(w in _TECHNICAL_NAME_WORDS for w in words) or _machine_identity(value))

def _name_list(value):
    parts=re.split(r"\s*[:;/|&]\s*",value.strip())
    return bool(parts) and all(_human_name(p) and len(p.split())>=2 for p in parts)

def semantic_map_field(key):
    """Generic map labels do not establish a personal record or username."""
    tail=re.split(r"[/.:]",str(key))[-1]
    canonical=_canonical(tail)
    if canonical in {"name","user","username","displayname"} or re.fullmatch(r"user[_ -]?name",tail,re.I):return "map_label"
    return key

class _ObjectPairs(list):
    pass

def _embedded_json_assessment(value):
    if len(value)>8*1024*1024:return set(),{"embedded_person_context_uninspected"}
    try:data=json.loads(value,object_pairs_hook=_ObjectPairs)
    except (ValueError,TypeError):return set(),set()
    except RecursionError:return set(),{"embedded_person_context_uninspected"}
    categories=set();reviews=set();stack=[(data,None,0)]
    while stack:
        item,field,depth=stack.pop()
        if depth>100:return categories,{"embedded_person_context_uninspected"}
        if isinstance(item,_ObjectPairs):
            personal=_canonical(field) in {"person","personal","personaldetails","employee","patient","student","beneficiary"}
            for key,child in item:
                key_categories,key_reviews=assess_value(key,"schema_label")
                categories.update(key_categories);reviews.update(key_reviews)
                hint="personname" if personal and _canonical(key)=="name" else semantic_map_field(key)
                stack.append((child,hint,depth+1))
        elif isinstance(item,list):stack.extend((child,field,depth+1) for child in item)
        else:
            found,reasons=assess_value(item,field);categories.update(found);reviews.update(reasons)
    return categories,reviews

_PROFILE_PATH=re.compile(r"(?:[A-Za-z]:[\\/]Users[\\/]|/(?:Users|home)/)([^\\/\r\n<>\"]{1,100})(?=[\\/]|$)",re.I)

def assess_value(value,field=None):
    """Return (confirmed human categories, unresolved review reason codes).

    Nonpersonal and uncertain values are retained. A review reason is evidence
    of ambiguity, never authority to erase the value.
    """
    found=set();reviews=set()
    if not _has_content(value):return found,reviews
    kind=classify_field(field);canonical=_policy_canonical(field);slot=_semantic_person_slot(field)
    if isinstance(value,str):
        text=_assessment_text(value)
        if text.lstrip().startswith(("{","[")):
            nested_found,nested_reviews=_embedded_json_assessment(text)
            found.update(nested_found);reviews.update(nested_reviews)
        matches=list(_EMAIL_RE.finditer(text))
        for match in matches:
            status=_email_assessment(*match.groups(),field)
            if status=="human":found.add("human_email_addresses")
            elif status=="review":reviews.add("ambiguous_email_identity")
            before=text[max(0,match.start()-124):match.start()]
            display=re.search(r"(?:^|[;\n,])\s*['\"]?([^<>\n;,:]{2,120})['\"]?\s*<$",before)
            if display and _name_list(display.group(1).strip().strip('\"\'')):
                found.add("human_names")
        if not matches and re.search(r"[\w.+%-]@[^\s@]*[\w]",text):
            reviews.add("encoded_contact_marker" if text!=value else "unparsed_contact_marker")
        if not matches and re.search(r"%(?:25)*40|&#(?:0*64|x0*40);|&commat;|\\(?:u0*040|U0*040|x40)",text,re.I):
            reviews.add("encoded_contact_marker")
        infrastructure_context=canonical in _INFRA_FIELDS | CATALOG_ID_FIELDS | NUMERIC_FIELDS | BILLING_DATE_FIELDS
        if _LABELED_GOV.search(text) or not infrastructure_context and _SSN.search(text):found.add("human_government_identifiers")
        if _LABELED_PHONE.search(text) or not infrastructure_context and kind in {"free_text","human_phone_numbers"} and _FORMATTED_PHONE.search(text):found.add("human_phone_numbers")
        if _LABELED_HOME.search(text):found.add("human_home_addresses")
        if _LABELED_BIRTH.search(text):found.add("human_birth_dates")
        if _LABELED_PERSON_SECRET.search(text):found.add("human_personal_credentials")
        for match in _LABELED_NAME.finditer(text):
            candidate=re.split(r"\s+(?:at|email|phone|tel|username|user\s+id|for|with)\s*[:=]?\s+",match.group(2).strip(),maxsplit=1,flags=re.I)[0]
            label=match.group(1).casefold()
            if _human_name(candidate) and (len(candidate.split())>=2 or label in {"first name","last name","full name","personal name","person name","author"}):found.add("human_names")
            elif label in {"user","user name"} and not _technical_person_candidate(candidate):reviews.add("ambiguous_person_identifier")
        for match in _ATTRIBUTED_NAME.finditer(text):
            candidate=re.split(r"\s+(?:during|at|on|for|with|email|phone|tel)\b",match.group(1).strip(),maxsplit=1,flags=re.I)[0].rstrip(".")
            if _human_name(candidate) and len(candidate.split())>=2:found.add("human_names")
            elif not _technical_person_candidate(candidate):reviews.add("ambiguous_person_name")
        # Short operational attributions can identify a person, but an application
        # can also use a server or carry a dated note. Require context, never erase
        # a bare given name or product label solely from these hints.
        for pattern in _ATTRIBUTION_HINTS:
            for match in pattern.finditer(text):
                candidate = match.group(1).strip()
                if (_human_name(candidate) and not _technical_person_candidate(candidate)
                        and candidate.casefold() not in _DATE_NOTE_LABELS):
                    reviews.add("ambiguous_person_name")
        for path in _PROFILE_PATH.finditer(text):
            profile=path.group(1).strip()
            if profile.casefold() in _PROFILE_MACHINE_NAMES or _machine_identity(profile):continue
            if canonical in {"personprofile","personalprofilepath","corroboratedpersonprofile"} or _named_local(profile.replace(" ",".")):
                found.add("human_usernames")
            else:reviews.add("ambiguous_person_profile_path")
        if kind=="human_names":
            strong=canonical in {"firstname","lastname","middlename","givenname","familyname","surname","maidenname","personinitials","humaninitials"}
            if _human_name(value,strong=strong) and (strong or len(value.split())>=2):found.add(kind)
            elif not matches and not _technical_person_candidate(value):reviews.add("ambiguous_person_name")
        elif kind=="human_usernames":
            if not _machine_identity(value):
                if canonical in {"personusername","personalusername","employeeusername","contactusername"} and re.fullmatch(r"(?:[A-Za-z0-9_.-]+\\)?[A-Za-z][A-Za-z0-9_.-]{1,63}",value.strip()):found.add(kind)
                elif _named_local(value):found.add(kind)
                else:reviews.add("ambiguous_person_identifier")
        elif kind=="personal_container" or slot:
            if not matches:
                if slot!="name" and _name_list(value):found.add("human_names")
                elif not _technical_person_candidate(value) and not re.match(r"^(?:arn:|ocid1\.|https?://|[/\\])",value):reviews.add("ambiguous_person_identifier" if re.fullmatch(r"[\w .-]+",value) else "ambiguous_person_container")
        if re.search(r"(?:IAMUser|AssumedRole|FederatedUser):",text,re.I) and not matches:
            terminal=text.rsplit(":",1)[-1]
            if not _technical_person_candidate(terminal) and not re.fullmatch(r"i-[0-9a-f]{8,17}",terminal) and (re.fullmatch(r"[a-z][a-z0-9._-]{1,39}",terminal) or re.fullmatch(r"\d{7,12}",terminal)):
                reviews.add("ambiguous_actor_identity")
    if kind=="human_phone_numbers" and isinstance(value,(str,int)) and 7<=len(re.sub(r"\D","",str(value)))<=15:found.add(kind)
    if kind in {"human_government_identifiers","human_employee_student_patient_identifiers"} and isinstance(value,(str,int)) and not isinstance(value,bool) and re.search(r"[A-Za-z0-9]",str(value)):found.add(kind)
    if kind in {"human_home_addresses","human_birth_dates","human_personal_financial_data","human_sensitive_personal_data","human_personal_credentials"} and not isinstance(value,(dict,list,tuple,bool)):found.add(kind)
    return found,set() if found else reviews

_NAME_FIELD_BOUNDARY = r"(?:name\s+of\s+server|server\s+name|purpose|point\s+of\s+contact|department\s+owner|owner|os|operating\s+system|host(?:name)?|phone|telephone|email|user\s*name|notes?)"
_LABELED_NAME=re.compile(r"\b(full\s+name|first\s+name|last\s+name|person(?:al)?\s+name|employee(?:\s+name)?|point\s+of\s+contact|department\s+owner|contact(?:\s+(?:person|name))?|owner\s+name|user(?:\s+name)?|author|prepared\s+by|approved\s+by|requested\s+by|assigned\s+to)\s*[:=]\s*['\"]?([^\n\r,;<>\"']{1,120}?)(?=\s+"+_NAME_FIELD_BOUNDARY+r"\s*[:=]|[\n\r,;<>\"']|$)",re.I)
_DATE_NOTE_LABELS = {"release", "version", "updated", "created", "modified", "reviewed", "snapshot", "build", "revision"}
_NOTE_PERSON = r"[A-Z][a-z]+(?:['’\-][A-Z]?[a-z]+)*(?:\s+[A-Z][a-z]+){0,2}"
_ATTRIBUTION_HINTS = (
    re.compile(r"(?:^|[.!?]\s+)("+_NOTE_PERSON+r")\s+\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b"),
    re.compile(r"(?:^|[\s(])("+_NOTE_PERSON+r")\s+(?i:uses?\s+(?:it\s+)?for)\b"),
    re.compile(r"(?i:service\s+account\s+for)\s+("+_NOTE_PERSON+r")\s+(?i:to\s+use)\b"),
)
_ATTRIBUTED_NAME=re.compile(r"\b(?:assigned\s+to|reviewed\s+by|prepared\s+by|approved\s+by|requested\s+by|created\s+by)\s*[:=]?\s+['\"]?([^\n\r,;<>\"']{1,120})",re.I)
_LABELED_PHONE=re.compile(r"\b(?:phone|telephone|mobile\s+phone|cell\s+phone|contact\s+number|fax)\s*[:=]\s*(\+?[\d ()-]{7,25}\d)",re.I)
_FORMATTED_PHONE=re.compile(r"(?<![\w\d])(?:\+1[ .-]?)?(?:\(\d{3}\)[ .-]?\d{3}[ .-]\d{4}|\d{3}[ .-]\d{3}[ .-]\d{4})(?![\w\d])")
_SSN=re.compile(r"(?<![\w\d])\d{3}-\d{2}-\d{4}(?![\w\d])")
_LABELED_GOV=re.compile(r"\b(?:ssn|social\s+security\s+(?:number|no)|passport\s*(?:number|no)?|driver'?s?\s+licen[cs]e\s*(?:number|no)?|national\s+(?:identity|identification|id)\s*(?:number|no)?)\s*[:=#]\s*['\"]?[A-Za-z0-9][A-Za-z0-9 -]{3,30}",re.I)
_LABELED_HOME=re.compile(r"\b(?:home|residential|personal\s+mailing)\s+address\s*[:=]\s*\S.{4,}",re.I)
_LABELED_BIRTH=re.compile(r"\b(?:date\s+of\s+birth|birth\s*date|dob)\s*[:=]\s*\S.{3,}",re.I)
_LABELED_PERSON_SECRET=re.compile(r"\b(?:personal|employee|person|user)\s+(?:password|pin|recovery\s+code|security\s+answer)\s*[:=]\s*\S+",re.I)

def detect_value(value,field=None):
    found,_=assess_value(value,field)
    return next(iter(sorted(found)),None)

def safe_field_name(field,index):
    if not isinstance(field,str):raise ScrubError("invalid_schema_label")
    return field

def detect_categories(value,field=None):
    return assess_value(value,field)[0]

def _numeric_safe(value):
    """Compatibility helper; parsing failure never authorizes removal."""
    if isinstance(value,bool):
        return False
    try:
        text=str(value).strip().replace(",","").rstrip("%")
        return bool(text) and Decimal(text).is_finite()
    except (ValueError,InvalidOperation):
        return False

def _enum_safe(value,kind):
    return detect_value(value) is None

@dataclass
class ScrubContext:
    counts: Counter=dataclass_field(default_factory=Counter)
    locations: dict=dataclass_field(default_factory=lambda:defaultdict(list))
    warnings: set=dataclass_field(default_factory=set)
    changed: int=0
    masked_spans: int=0
    masked_characters: int=0
    max_locations: int=30
    inspected: int=0
    retained: int=0
    max_depth: int=100
    containers_cleared: int=0
    leaf_values_cleared: int=0
    cleared_fields: set=dataclass_field(default_factory=set)
    review_counts: Counter=dataclass_field(default_factory=Counter)
    review_locations: dict=dataclass_field(default_factory=lambda:defaultdict(list))
    resolved_review_counts: Counter=dataclass_field(default_factory=Counter)
    resolved_review_locations: dict=dataclass_field(default_factory=lambda:defaultdict(list))
    review_occurrences: int=0
    resolved_review_occurrences: int=0
    review_location_coverage_complete: bool=True
    removal_location_coverage_complete: bool=True
    review_decisions: dict=dataclass_field(default_factory=dict)
    applied_review_decisions: list=dataclass_field(default_factory=list)
    review_location_sink: Any=None
    removal_location_sink: Any=None
    location_sink: Any=None
    _applied_decision_locations: set=dataclass_field(default_factory=set,repr=False)
    # Complete event identities are independent of capped presentation samples.
    _review_events: dict=dataclass_field(default_factory=dict,repr=False)
    _review_item_locations: set=dataclass_field(default_factory=set,repr=False)
    _resolved_review_item_locations: set=dataclass_field(default_factory=set,repr=False)

    def field_removed(self,field):
        name=_canonical(field)
        self.cleared_fields.add(name if name in _ALL_POLICY_FIELDS else "other_field_with_human_pii")

    def _record_mask(self, original, masked, field, location, spans):
        if original == masked:return
        self.changed += 1
        self.masked_spans += len(span_union(spans))
        self.masked_characters += sum(b-a for a,b in span_union(spans))
        self.field_removed(field)
        for category in sorted({s['category'] for s in spans}):
            category_spans=span_union([s for s in spans if s['category']==category])
            self.note(category,location,_action=False,spans=category_spans)

    def note(self,category,location="",count=1,_action=True,spans=None):
        if category not in _GROUPS:raise ScrubError('invalid_mask_category')
        count=max(0,int(count));self.counts[category]+=count
        if _action:self.changed+=count
        if location and _SAFE_LOCATION.fullmatch(location):
            if location not in self.locations[category] and len(self.locations[category])<self.max_locations:
                self.locations[category].append(location)
            elif location not in self.locations[category] and self.removal_location_sink is None and self.location_sink is None:
                self.removal_location_coverage_complete=False
            sink=self.removal_location_sink or self.location_sink
            if sink is not None:
                ranges=[{'start':a,'end':b} for a,b in (spans or [])]
                sink({'category':category,'location':location,'count':count,'spans':ranges,
                      'masked_characters':sum(s['end']-s['start'] for s in ranges)})
        else:self.removal_location_coverage_complete=False
        if count>1:self.removal_location_coverage_complete=False

    def note_review(self,reason,location="",count=1,_item=True,_resolved=False):
        if reason not in REVIEW_REASON_CODES:reason="ambiguous_person_container"
        count=max(0,int(count))
        valid=bool(location and _SAFE_LOCATION.fullmatch(location))
        if valid and count == 1:
            key = (reason, location)
            if key in self._review_events:
                if self._review_events[key] != bool(_resolved):
                    raise ScrubError('review_event_resolution_conflict')
                return
            self._review_events[key] = bool(_resolved)
            if location not in self._review_item_locations:
                self._review_item_locations.add(location)
                self.review_occurrences += 1
            if _resolved and location not in self._resolved_review_item_locations:
                self._resolved_review_item_locations.add(location)
                self.resolved_review_occurrences += 1
        else:
            # Aggregate or unlocatable events cannot establish complete coverage.
            self.review_location_coverage_complete=False
            if _item:self.review_occurrences+=count
            if _resolved and _item:self.resolved_review_occurrences+=count
        self.review_counts[reason]+=count
        if _resolved:self.resolved_review_counts[reason]+=count
        if valid:
            if location not in self.review_locations[reason] and len(self.review_locations[reason])<self.max_locations:self.review_locations[reason].append(location)
            elif location not in self.review_locations[reason] and self.review_location_sink is None:self.review_location_coverage_complete=False
            if _resolved and location not in self.resolved_review_locations[reason] and len(self.resolved_review_locations[reason])<self.max_locations:self.resolved_review_locations[reason].append(location)
            if self.review_location_sink is not None:self.review_location_sink({"reason":reason,"location":location,"count":count,"resolved":_resolved})

    def apply_review_decision(self,value,field=None,location=""):
        """Apply one validated, exact-coordinate mask/retain decision."""
        if location not in self.review_decisions:return False,value
        if not _SAFE_LOCATION.fullmatch(location):raise ScrubError('invalid_review_decision_location')
        if isinstance(value,(dict,list,tuple)):raise ScrubError('review_decision_requires_scalar')
        from review_support import validate_decisions
        decision=validate_decisions({location:self.review_decisions[location]})[location]
        if location in self._applied_decision_locations:raise ScrubError('review_decision_applied_twice')
        _,reviews=detect_pii_spans(value,field)
        # Explicit human PII inside a protected identifier cannot be waived by a
        # retain decision. Preserve its bytes and keep the readiness gate closed.
        blockers={'protected_identifier_contains_pii','schema_label_contains_pii',
                  'type_masking_conflict','formula_pii_requires_review','unsupported_content_uninspected'}
        for index,review in enumerate(sorted(reviews)):
            self.note_review(review,location,_item=index==0,_resolved=review not in blockers)
        self._applied_decision_locations.add(location)
        self.applied_review_decisions.append(dict(decision,location=location))
        if decision['action']=='mask':
            spans=decision['spans'];masked,_,needs=mask_text(value,field,spans)
            for index,review in enumerate(sorted(needs)):self.note_review(review,location,_item=index==0)
            self._record_mask(value,masked,field,location,spans)
            return True,masked
        return True,value

    def warn(self,code):
        if re.fullmatch(r"[a-z][a-z0-9_]{0,79}",code):
            self.warnings.add(code)

    def scrub(self,value,field=None,location="",_depth=0,spans=None):
        if _depth>self.max_depth:raise ScrubError('nesting_limit_exceeded')
        if not _has_content(value):return value
        self.inspected+=1
        applied,reviewed_value=self.apply_review_decision(value,field,location)
        if applied:
            if reviewed_value==value:self.retained+=1
            return reviewed_value
        if isinstance(value,dict):
            out={};personal=classify_field(field)=='personal_container'
            for index,(key,item) in enumerate(value.items(),1):
                child=f"{location or 'root'}.k{index}"
                _,key_reviews=detect_pii_spans(key,'schema_label')
                for n,reason in enumerate(sorted(key_reviews)):self.note_review(reason,child,_item=n==0)
                child_hint='personname' if personal and _canonical(key)=='name' else semantic_map_field(key)
                if is_protected_resource_field(field):
                    cats,needs=assess_value(item,child_hint)
                    if cats and not assess_value(item,field)[0]:self.note_review('protected_identifier_contains_pii',child)
                hint=field if is_protected_resource_field(field) else child_hint
                out[key]=self.scrub(item,hint,child,_depth+1)
            return out
        if isinstance(value,(list,tuple)):
            out=[self.scrub(item,field,f"{location or 'root'}.i{i}",_depth+1) for i,item in enumerate(value,1)]
            return tuple(out) if isinstance(value,tuple) else out
        found,reviews=detect_pii_spans(value,field)
        if spans is not None and spans:
            found=[{'start':a,'end':b,'category':c} for a,b,c in validate_spans(value,spans)]
            masked,_,needs=mask_text(value,field,found);reviews.update(needs)
        elif spans is not None:
            found=[];masked=value
        else:
            masked,_,needs=mask_text(value,field);reviews.update(needs)
        for index,reason in enumerate(sorted(reviews)):self.note_review(reason,location,_item=index==0)
        self._record_mask(value,masked,field,location,found)
        if masked==value:self.retained+=1
        return masked

    def safe_report(self):
        return {"categories":dict(sorted(self.counts.items())),
                "locations":{key:list(self.locations[key]) for key in sorted(self.locations)},
                "warnings":sorted(self.warnings),"removed_items":self.changed,
                "masked_items":self.changed,"masked_spans":self.masked_spans,"masked_characters":self.masked_characters,
                "inspected_values":self.inspected,"retained_values":self.retained,
                "containers_cleared":self.containers_cleared,"leaf_values_cleared":self.leaf_values_cleared,
                "cleared_fields":[],"masked_fields":sorted(self.cleared_fields),
                "review_counts":dict(sorted(self.review_counts.items())),
                "review_locations":{key:list(self.review_locations[key]) for key in sorted(self.review_locations)},
                "review_occurrences":self.review_occurrences,
                "resolved_review_counts":dict(sorted(self.resolved_review_counts.items())),
                "resolved_review_locations":{key:list(self.resolved_review_locations[key]) for key in sorted(self.resolved_review_locations)},
                "resolved_review_occurrences":self.resolved_review_occurrences,
                "unresolved_review_counts":{key:count-self.resolved_review_counts[key] for key,count in sorted(self.review_counts.items()) if count>self.resolved_review_counts[key]},
                "unresolved_review_occurrences":self.review_occurrences-self.resolved_review_occurrences,
                "review_location_coverage_complete":self.review_location_coverage_complete,
                "removal_location_coverage_complete":self.removal_location_coverage_complete,
                "applied_review_decisions":list(self.applied_review_decisions),
                "unused_review_decision_locations":sorted(key for key in self.review_decisions if key not in self._applied_decision_locations and _SAFE_LOCATION.fullmatch(key)),
                "count_basis":"masked_items_categories_overlap_not_unique_people"}

from pii_masking import detect_pii_spans, mask_text, is_protected_resource_field, validate_spans, span_union
