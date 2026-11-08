#!/usr/bin/env python3
import sys
sys.path.insert(0,'/home/ubuntu/services/micro-sentinel/bin')
from request_understanding import classify,clean_path
def main():
 assert clean_path('/api/items?token=SECRET&x=1')=='/api/items'
 assert classify('GET','/',200,baseline_count=20)['class']=='normal_like'
 assert classify('POST','/login',200,baseline_count=20)['class']=='normal_like'
 assert classify('GET','/new-page',404)['class']=='normal_like'
 assert classify('GET','/.env',404)['class']=='unusual_uncertain'
 x=classify('GET','/.env',404,source_events=30,unique_paths=15,probe_hits=5)
 assert x['class']=='suspicious_pattern'
 y=classify('GET','/health',502,baseline_count=20)
 assert y['class']=='normal_like' and 'server_error_not_hostility' in y['reasons']
 z=classify('TRACE','/',200)
 assert z['class']=='unusual_uncertain'
 print('PASS: normal / uncertain / suspicious + privacy sanitization')
if __name__=='__main__':main()
