"""Synthetic structured-data privacy, location and preservation regressions."""
from __future__ import annotations
import csv
from datetime import datetime, timezone
from decimal import Decimal
import json
from pathlib import Path
import struct
import tempfile
import unittest

from scrub_core import ScrubContext
import scrub_structured as adapter

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
except ImportError:
    pa = pq = None


class StructuredRegression(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="structured-regression-")
        self.root=Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()

    def test_csv_json_cell_span_mask_and_header_row_one(self):
        source,output=self.root/"source.csv",self.root/"output.csv"
        benign='{"user_name":"CorePlatform","resource_id":"cluster-9","tags":{"team":"Billing"}}'
        private='{"contact":{"email":"avery.stone@example.test"},"cost":12}'
        with source.open("w",newline="") as stream:
            writer=csv.writer(stream);writer.writerow(["resourceTags/user:Name","Tags","Cost"])
            writer.writerow(["west-company",private,"1,234.567890123456789"])
            writer.writerow(["prod-db",benign,"0.0000000000000000001"])
        events=[];ctx=ScrubContext(removal_location_sink=events.append)
        metrics=adapter.scrub_csv(source,output,ctx)
        with output.open(newline="") as stream:rows=list(csv.reader(stream))
        self.assertEqual(rows[0],["resourceTags/user:Name","Tags","Cost"])
        self.assertEqual(rows[1],["west-company",private.replace("avery.stone@example.test","X"*len("avery.stone@example.test")),"1,234.567890123456789"])
        self.assertEqual(rows[2],["prod-db",benign,"0.0000000000000000001"])
        self.assertEqual([(e["category"],e["location"],e["count"]) for e in events],[("human_email_addresses","r2.c2",1)])
        self.assertEqual(metrics["rows"],2)

    def test_uncertain_owner_retained_and_exact_span_decision_can_mask(self):
        source=self.root/"source.csv"
        source.write_text("Owner,Cost\nopaquehandle,12.30\n")
        events=[];ctx=ScrubContext(review_location_sink=events.append)
        adapter.scrub_csv(source,self.root/"retained.csv",ctx)
        self.assertIn("opaquehandle",(self.root/"retained.csv").read_text())
        self.assertTrue(events)
        self.assertTrue(all(event["location"]=="r2.c1" for event in events))
        decisions={"r2.c1":{"action":"mask","spans":[{"start":0,"end":12,"category":"human_usernames"}],"reason_code":"explicit_person_identifier"}}
        ctx=ScrubContext(review_decisions=decisions)
        adapter.scrub_csv(source,self.root/"masked.csv",ctx)
        with (self.root/"masked.csv").open(newline="") as stream:rows=list(csv.reader(stream))
        self.assertEqual(rows[1],["X"*12,"12.30"])
        self.assertEqual(len(ctx.applied_review_decisions),1)

    @unittest.skipUnless(pa,"pyarrow unavailable")
    def test_parquet_global_record_and_map_entry_locations_across_batches(self):
        size=32770
        values=[[("user_name","CorePlatform"),("contact","support@example.test")]]*size
        values=list(values)
        values[0]=[("user_name","CorePlatform"),("contact","avery.stone@example.test")]
        values[16384]=[("contact","blair.reed@example.test"),("user_name","Billing-Group")]
        values[32769]=[("resource","cluster-9"),("user_name","CorePlatform"),("contact","casey.lane@example.test")]
        source,output=self.root/"source.parquet",self.root/"output.parquet"
        table=pa.table({"cost":pa.array([Decimal("12.1234567890123456789")]*size,type=pa.decimal128(24,19)),
                        "resource_id":pa.array(["cloud-123456789012"]*size),
                        "resource_tags":pa.array(values,type=pa.map_(pa.string(),pa.string()))})
        pq.write_table(table,source,row_group_size=10003)
        events=[];ctx=ScrubContext(removal_location_sink=events.append)
        metrics=adapter.scrub_parquet(source,output,ctx)
        result=pq.read_table(output)
        self.assertEqual(result.column(0).to_pylist(),table.column(0).to_pylist())
        self.assertEqual(result.column(1).to_pylist(),table.column(1).to_pylist())
        self.assertEqual([event["location"] for event in events],["r1.c3.k2","r16385.c3.k1","r32770.c3.k3"])
        self.assertEqual(result.column(2)[0].as_py(),[("user_name","CorePlatform"),("contact","X"*len("avery.stone@example.test"))])
        self.assertEqual(result.column(2)[16384].as_py(),[("contact","X"*len("blair.reed@example.test")),("user_name","Billing-Group")])
        self.assertEqual(metrics["rows"],size)

    @unittest.skipUnless(pa,"pyarrow unavailable")
    def test_arrow_preserves_nanosecond_time_float_bits_and_safe_nullability(self):
        source,output=self.root/"source.parquet",self.root/"output.parquet"
        schema=pa.schema([pa.field("usage_start_date",pa.timestamp("ns",tz="UTC"),nullable=False),
                          pa.field("cost",pa.float64(),nullable=False),pa.field("Employee ID",pa.int64(),nullable=False)])
        floats=pa.array([0.12345678901234568,-0.0,float("nan")],type=pa.float64())
        times=pa.array([1720000000000000001,1720000000000000002,1720000000000000003],type=pa.int64()).cast(schema[0].type)
        table=pa.Table.from_arrays([times,floats,pa.array([101,102,103])],schema=schema)
        pq.write_table(table,source)
        ctx=ScrubContext();adapter.scrub_parquet(source,output,ctx);result=pq.read_table(output)
        self.assertEqual(result.schema[0],schema[0]);self.assertEqual(result.schema[1],schema[1])
        self.assertFalse(result.schema[2].nullable)
        self.assertTrue(result.column(0).combine_chunks().view(pa.int64()).equals(times.view(pa.int64())))
        self.assertTrue(result.column(1).combine_chunks().view(pa.uint64()).equals(floats.view(pa.uint64())))
        self.assertEqual(result.column(2).to_pylist(),[101,102,103])
        self.assertEqual(ctx.review_counts["type_masking_conflict"],3)

    @unittest.skipUnless(pa,"pyarrow unavailable")
    def test_nested_lists_map_entry_ordinals_and_original_order(self):
        source,output=self.root/"source.parquet",self.root/"output.parquet"
        typ=pa.list_(pa.map_(pa.string(),pa.string()))
        value=[[[('user_name','CorePlatform'),('contact','avery.stone@example.test')],
                [('contact','support@example.test')]],[],None]
        table=pa.table({"config":pa.array(value,type=typ)})
        pq.write_table(table,source)
        events=[];ctx=ScrubContext(removal_location_sink=events.append)
        adapter.scrub_parquet(source,output,ctx)
        self.assertEqual([event["location"] for event in events],["r1.c1.i1.k2"])
        result=pq.read_table(output)
        self.assertEqual(result.column(0)[0].as_py(),[[('user_name','CorePlatform'),('contact','X'*len('avery.stone@example.test'))],[('contact','support@example.test')]])
        self.assertEqual(result.column(0)[1].as_py(),[]);self.assertIsNone(result.column(0)[2].as_py())


if __name__=="__main__":unittest.main(verbosity=2)
