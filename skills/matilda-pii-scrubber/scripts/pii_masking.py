"""Position-preserving human PII masks. No originals or identity maps persist."""
from __future__ import annotations
import html
from functools import lru_cache
import json
import re
import scrub_core as core

_RESOURCE_FIELDS = set('''serialnumber resourceguid resourceuuid virtualmachineuuid databaseuuid vm vmid vmname virtualmachine virtualmachineid virtualmachinename hostname hostid host hostuuid fqdn computer computername machinename machineid database databaseid databasename dbid dbname resource resourceid resourcename resourcearn arn ocid instance instanceid instancename instanceuuid uuid guid biosuuid objectid moref mobid cluster clusterid clustername datacenter datacenterid datastore datastoreid datastorename disk diskid diskname volume volumeid volumename network networkid networkname subnet subnetid subnetname vpc vpcid securitygroupid loadbalancerid loadbalancername bucket bucketname accountid payeraccountid usageaccountid linkedaccountid subscriptionid tenantid tenancyid projectid compartmentid path resourcepath logdirectory snapshotdirectory suspenddirectory configurationfile vmxpath ip ipaddress ipv4 ipv6 mac macaddress endpoint serviceprincipal machineprincipal'''.split())
_SCHEMA_FIELDS = {'schema_label', 'sheet_name', 'xml_schema_label'}
_RESOURCE_FIELDS.update({'billingrecordid', 'cloudaccountname'})
# Namespaced/custom fields can suffix explicit cloud resource concepts. Keep
# this bounded to infrastructure keys, never arbitrary owner/user/tag fields.
_RESOURCE_SUFFIX_FIELDS = set('''cluster clusterid clustername vpc vpcid vpcname subnet subnetid subnetname networkid networkname resourceid resourcename resourcearn instanceid instancename vmid vmname hostid hostname databaseid databasename volumeid volumename diskid diskname bucketid bucketname securitygroupid loadbalancerid loadbalancername'''.split())
_PLACEHOLDER = re.compile(r'X+')

def is_protected_resource_field(field):
    return _protected_resource_name(str(field or ''))

@lru_cache(maxsize=4096)
def _protected_resource_name(raw):
    tail=re.split(r'[/.:]',raw)[-1]
    tail=re.sub(r'^(?:resource[_ -]?tags?|tags?|user)[_ -]+','',tail,flags=re.I)
    if any(core._canonical(item) in _RESOURCE_FIELDS for item in (raw,tail)) or core._policy_canonical(raw) in _RESOURCE_FIELDS:
        return True
    words = re.split(r'[/.:_\s-]+', re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', raw).lower())
    return any(''.join(words[-size:]) in _RESOURCE_SUFFIX_FIELDS for size in (1,2,3) if len(words) >= size)

def _decode_map(value):
    """Decode for assessment only, keeping each decoded char's source extent."""
    text=value;positions=[(i,i+1) for i in range(len(value))]
    patterns=(re.compile(r'(?:%[0-9a-fA-F]{2})+'),
              re.compile(r'&(?:#[xX][0-9a-fA-F]+|#\d+|[A-Za-z][A-Za-z0-9]+);'),
              re.compile(r'\\(?:u[dD][89aAbB][0-9a-fA-F]{2}\\u[dD][c-fC-F][0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|["\\/])'))
    for _ in range(5):
        before=text
        for kind,pattern in enumerate(patterns):
            pieces=[];mapped=[];last=0
            for match in pattern.finditer(text):
                raw=match.group();decoded=raw
                try:
                    if kind==0:decoded=bytes.fromhex(raw.replace('%','')).decode('utf-8')
                    elif kind==1:decoded=html.unescape(raw)
                    elif raw.startswith('\\x'):decoded=chr(int(raw[2:],16))
                    else:decoded=json.loads('"'+raw+'"')
                except (ValueError,UnicodeError):pass
                pieces.append(text[last:match.start()]);mapped.extend(positions[last:match.start()])
                pieces.append(decoded)
                if decoded==raw:mapped.extend(positions[match.start():match.end()])
                elif kind==0:
                    byte_offset=0
                    for character in decoded:
                        start=match.start()+3*byte_offset;byte_offset+=len(character.encode('utf-8'))
                        end=match.start()+3*byte_offset
                        mapped.append((positions[start][0],positions[end-1][1]))
                else:mapped.extend([(positions[match.start()][0],positions[match.end()-1][1])]*len(decoded))
                last=match.end()
            pieces.append(text[last:]);mapped.extend(positions[last:]);text=''.join(pieces);positions=mapped
        if text==before:break
    return text,positions

def validate_spans(value, spans):
    if not isinstance(value,str) or not isinstance(spans,(list,tuple)) or not spans:
        raise core.ScrubError('invalid_mask_spans')
    result=[]
    for span in spans:
        if not isinstance(span,dict) or set(span)!={'start','end','category'}:
            raise core.ScrubError('invalid_mask_span')
        start,end,category=span['start'],span['end'],span['category']
        if type(start) is not int or type(end) is not int or not 0<=start<end<=len(value) or category not in core._GROUPS:
            raise core.ScrubError('invalid_mask_span')
        result.append({'start':start,'end':end,'category':category})
    return sorted({(s['start'],s['end'],s['category']) for s in result})

def span_union(spans):
    merged=[]
    for start,end in sorted((s['start'],s['end']) if isinstance(s,dict) else s[:2] for s in spans):
        if merged and start<=merged[-1][1]:merged[-1][1]=max(end,merged[-1][1])
        else:merged.append([start,end])
    return merged

def _embedded_spans(value):
    """Inspect JSON leaf strings without rewriting JSON syntax or native types."""
    decoder=json.JSONDecoder();spans=[];reviews=set();length=len(value)
    def ws(i):
        while i<length and value[i].isspace():i+=1
        return i
    def parse(i,field=None,personal=False,depth=0):
        if depth>100:raise ValueError()
        i=ws(i)
        if i>=length:raise ValueError()
        if value[i]=='{':
            i=ws(i+1);seen=set()
            if value[i:i+1]=='}':return i+1
            while True:
                if value[i:i+1]!='"':raise ValueError()
                key,end=decoder.raw_decode(value,i)
                if key in seen:raise ValueError()
                seen.add(key)
                _,key_reviews=detect_pii_spans(value[i+1:end-1],'schema_label');reviews.update(key_reviews)
                i=ws(end)
                if value[i:i+1]!=':':raise ValueError()
                hint='personname' if personal and core._canonical(key)=='name' else core.semantic_map_field(key)
                if is_protected_resource_field(field):
                    child_value,_=decoder.raw_decode(value,ws(i+1))
                    child_found,_=core.assess_value(child_value,hint)
                    if child_found:reviews.add('protected_identifier_contains_pii')
                    hint=field
                i=ws(parse(i+1,hint,personal or core.classify_field(key)=='personal_container',depth+1))
                if value[i:i+1]=='}':return i+1
                if value[i:i+1]!=',':raise ValueError()
                i=ws(i+1)
        if value[i]=='[':
            i=ws(i+1)
            if value[i:i+1]==']':return i+1
            while True:
                i=ws(parse(i,field,personal,depth+1))
                if value[i:i+1]==']':return i+1
                if value[i:i+1]!=',':raise ValueError()
                i=ws(i+1)
        item,end=decoder.raw_decode(value,i)
        if isinstance(item,str):
            found,needs=detect_pii_spans(value[i+1:end-1],field)
            spans.extend({'start':s['start']+i+1,'end':s['end']+i+1,'category':s['category']} for s in found);reviews.update(needs)
        else:
            found,needs=core.assess_value(item,field);reviews.update(needs)
            if found:reviews.add('type_masking_conflict')
        return end
    try:
        if ws(parse(0))!=length:raise ValueError()
    except (ValueError,IndexError,RecursionError,json.JSONDecodeError):
        return [],{'embedded_person_context_uninspected'}
    return spans,reviews

def _whole_personal_scalar(text, kind, canonical):
    """Conservative evidence that a personal field contains only one value.

    Field names supply context, not permission to erase arbitrary prose. Mixed
    or unfamiliar representations require exact reviewed spans instead.
    """
    value = text.strip()
    if not value or re.search(r"[;|\r\n]|(?:^|\s)[A-Za-z][A-Za-z _-]{0,40}\s*[:=]", value):
        return False
    if kind == 'human_names':
        strong = canonical in {'firstname', 'lastname', 'middlename', 'givenname',
                               'familyname', 'surname', 'maidenname', 'personinitials', 'humaninitials'}
        return core._human_name(value, strong=strong)
    if kind == 'human_usernames':
        return bool(re.fullmatch(r"(?:[A-Za-z0-9_.-]+\\)?[A-Za-z][A-Za-z0-9_.-]{1,63}", value))
    if kind in {'human_government_identifiers', 'human_employee_student_patient_identifiers'}:
        return bool(re.fullmatch(r"(?:[A-Za-z0-9]+(?:[-/][A-Za-z0-9]+)*|[0-9]+(?: [0-9]+)+)", value)
                    and any(character.isdigit() for character in value))
    if kind == 'human_phone_numbers':
        return bool(re.fullmatch(r"\+?[0-9 ()./-]+", value)
                    and 7 <= len(re.sub(r"\D", '', value)) <= 15)
    if kind == 'human_birth_dates':
        return bool(re.fullmatch(r"(?:\d{4}-\d{1,2}-\d{1,2}|\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})", value))
    if kind == 'human_personal_financial_data':
        return bool(re.fullmatch(r"(?:[A-Z]{3} )?[$€£]?[-+]?\d[\d., /-]*", value)
                    or re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9 ]{8,30}", value))
    if kind == 'human_personal_credentials':
        return bool(re.fullmatch(r"[^\s:;|=,]+", value))
    if kind == 'human_home_addresses':
        # Unfamiliar/international layouts remain available for context review.
        return bool(re.fullmatch(r"\d+[A-Za-z]?\s+[\w .,'’#/-]+", value)
                    and not core._technical_person_candidate(value))
    if kind == 'human_sensitive_personal_data':
        return bool(re.fullmatch(r"[^\W\d_]+(?:[ '’-][^\W\d_]+)*", value, re.UNICODE)
                    and not core._technical_person_candidate(value))
    return False

def _raw_spans(value,field=None):
    if not isinstance(value,str):
        categories,reviews=core.assess_value(value,field)
        return [],set(reviews)|({'type_masking_conflict'} if categories or value is not None and core.classify_field(field).startswith('human_') else set())
    if not value or _PLACEHOLDER.fullmatch(value.strip()):return [],set()
    if re.match(r'^\s*(?:\{\s*["}]|\[\s*(?:["{\[\]0-9-]|true\b|false\b|null\b))',value):
        return _embedded_spans(value)
    text,positions=_decode_map(value)
    categories,reviews=core.assess_value(value,field);reviews=set(reviews);spans=[]
    def add(start,end,category):
        while start<end and text[start].isspace():start+=1
        while end>start and text[end-1].isspace():end-=1
        if end>start:
            spans.append({'start':positions[start][0],'end':positions[end-1][1],'category':category})
    kind=core.classify_field(field);canonical=core._policy_canonical(field)
    matches=list(core._EMAIL_RE.finditer(text))
    for match in matches:
        status=core._email_assessment(*match.groups(),field)
        if status=='human':add(match.start(),match.end(),'human_email_addresses')
        elif status=='review':reviews.add('ambiguous_email_identity')
        before=text[max(0,match.start()-124):match.start()]
        display=re.search(r'(?:^|[;\n,])\s*[\'\"]?([^<>\n;,:]{2,120})[\'\"]?\s*<$' ,before)
        if display and core._name_list(display.group(1).strip().strip('\"\'')):
            offset=max(0,match.start()-124);a=offset+display.start(1);b=offset+display.end(1)
            while a<b and (text[a].isspace() or text[a] in '\"\''):a+=1
            while b>a and (text[b-1].isspace() or text[b-1] in '\"\''):b-=1
            add(a,b,'human_names')
    for match in core._LABELED_NAME.finditer(text):
        raw=match.group(2);candidate=re.split(r'\s+(?:at|email|phone|tel|username|user\s+id|for|with)\s*[:=]?\s+',raw,maxsplit=1,flags=re.I)[0]
        if core._human_name(candidate) and (len(candidate.split())>=2 or match.group(1).lower() in {'first name','last name','full name','personal name','person name','author'}):
            add(match.start(2),match.start(2)+len(candidate),'human_names')
    for match in core._ATTRIBUTED_NAME.finditer(text):
        raw=match.group(1);candidate=re.split(r'\s+(?:during|at|on|for|with|email|phone|tel)\b|[.!?](?:\s|$)',raw,maxsplit=1,flags=re.I)[0]
        if core._human_name(candidate) and len(candidate.split())>=2:add(match.start(1),match.start(1)+len(candidate),'human_names')
    if 'human_phone_numbers' in categories:
        for match in core._FORMATTED_PHONE.finditer(text):add(match.start(),match.end(),'human_phone_numbers')
        for match in core._LABELED_PHONE.finditer(text):add(match.start(1),match.end(1),'human_phone_numbers')
    if 'human_government_identifiers' in categories:
        for match in core._SSN.finditer(text):add(match.start(),match.end(),'human_government_identifiers')
        for match in re.finditer(r'\b(?:ssn|passport(?:\s+number)?|national\s+id|driver\s+license)\s*[:=#]\s*([A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)',text,re.I):add(match.start(1),match.end(1),'human_government_identifiers')
    for match in core._PROFILE_PATH.finditer(text):
        profile=match.group(1).strip()
        if profile.casefold() in core._PROFILE_MACHINE_NAMES or core._machine_identity(profile):continue
        if canonical in {'personprofile','personalprofilepath','corroboratedpersonprofile'} or core._named_local(profile.replace(' ','.')):
            add(match.start(1),match.end(1),'human_usernames')
    if 'human_personal_credentials' in categories:
        for match in re.finditer(r'\b(?:personal|employee|person|user)\s+(?:password|pin|recovery\s+code|security\s+answer)\s*[:=]\s*([^\s;|,]+)',text,re.I):add(match.start(1),match.end(1),'human_personal_credentials')
    if 'human_birth_dates' in categories:
        for match in re.finditer(r'\b(?:dob|date\s+of\s+birth|birthdate)\s*[:=]\s*(\d{4}-\d{1,2}-\d{1,2}|\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})\b',text,re.I):add(match.start(1),match.end(1),'human_birth_dates')
    # A personal field can contain mixed prose. Prefer already bounded spans;
    # use a whole-scalar mask only when its complete representation is personal.
    if (kind.startswith('human_') and kind in categories
            and kind != 'human_email_addresses'
            and not any(span['category'] == kind for span in spans)
            and _whole_personal_scalar(text, kind, canonical)):
        add(0, len(text), kind)
    if 'human_names' in categories and (kind=='personal_container' or core._semantic_person_slot(field)) and core._name_list(text):
        for match in re.finditer(r'[^:;/|&]+',text):add(match.start(),match.end(),'human_names')
    # A technical fragment must not hide an unbounded name elsewhere in a
    # personal-name field. Preserve the cell and ask for exact boundaries.
    if kind == 'human_names' and not any(span['category'] == kind for span in spans):
        fragments = re.split(r'[;|\r\n]', text)
        if len(fragments) > 1 and any(core._human_name(fragment.strip())
                                      and len(fragment.split()) >= 2 for fragment in fragments):
            reviews.add('pii_span_unresolved')
    covered={s['category'] for s in spans}
    if categories-covered:reviews.add('pii_span_unresolved')
    unique=sorted({(s['start'],s['end'],s['category']) for s in spans})
    return [{'start':a,'end':b,'category':c} for a,b,c in unique],reviews

def detect_pii_spans(value,field=None):
    spans,reviews=_raw_spans(value,field)
    if is_protected_resource_field(field):
        if spans:reviews.add('protected_identifier_contains_pii')
        elif reviews:reviews.add('protected_identifier_review')
        return [],reviews
    if str(field or '') in _SCHEMA_FIELDS:
        if spans:reviews.add('schema_label_contains_pii')
        return [],reviews
    return spans,reviews

def mask_text(value,field=None,spans=None):
    if spans is None:
        found,reviews=detect_pii_spans(value,field)
    else:
        if not spans:return value,set(),detect_pii_spans(value,field)[1]
        if is_protected_resource_field(field):raise core.ScrubError('protected_identifier_mask_forbidden')
        if str(field or '') in _SCHEMA_FIELDS:raise core.ScrubError('schema_label_mask_forbidden')
        found=[{'start':a,'end':b,'category':c} for a,b,c in validate_spans(value,spans)];reviews=set()
    if not isinstance(value,str) or not found:return value,set(),reviews
    characters=list(value)
    for start,end in span_union(found):characters[start:end]='X'*(end-start)
    masked=''.join(characters)
    if value.lstrip().startswith(('{','[')):
        try:json.loads(masked)
        except (ValueError,RecursionError):return value,set(),reviews|{'type_masking_conflict'}
    return masked,{s['category'] for s in found},reviews
