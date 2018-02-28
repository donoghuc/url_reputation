#!/usr/bin/python

import json, sys, getopt, os, codecs
import pandas as pd
import params

def usage():
    '''HW PRE DIFINED FUNCTION FOR HOME GROWN ARGPARSE'''
    print("Usage: %s --file=[filename]" % sys.argv[0])
    sys.exit()


def get_target_file():
    ''' this is the algorithm provided for parser. would use argparse personally...'''
    
    file=''
    myopts, args = getopt.getopt(sys.argv[1:], "", ["file="])
    
    for o, a in myopts:
        if o in ('-f, --file'):
            file=a
        else:
            usage()

    if len(file) == 0:
        usage()

    return file


def make_dataframe(file):
    '''build a dataframe from JSON input'''
    # read the target file
    with codecs.open(file, "r", encoding='utf-8', errors='ignore') as fdata:
        urldata = json.load(fdata)
    # build a dataframe
    build_frame = dict(query=[],
                    malicious_url=[],
                    port=[],
                    host_len=[],
                    file_extension=[],
                    path=[],
                    scheme=[],
                    domain_age_days=[],
                    path_tokens=[],
                    domain_tokens=[],
                    tld=[],
                    ips=[],
                    mxhosts=[],
                    registered_domain=[],
                    alexa_rank=[],
                    fragment=[],
                    host=[],
                    url_len=[],
                    num_path_tokens=[],
                    path_len=[],
                    num_domain_tokens=[],
                    default_port=[],
                    url=[])
    
    for record in urldata:
        for k in build_frame.keys():
            build_frame[k].append(record.get(k,"NA"))
    
    return pd.DataFrame(build_frame)


def clean_df(df):
    ''' make sure numeric rows are integers'''
    df['alexa_rank'] = df['alexa_rank'].map(lambda x: int(x) if x else 0)
    df['domain_age_days'] = df['domain_age_days'].map(lambda x: int(x) if x else 0)
    df['host_len'] = df['host_len'].map(lambda x: int(x) if x else 0)
    df['malicious_url'] = df['malicious_url'].map(lambda x: int(x) if x else 0)
    df['path_len'] = df['path_len'].map(lambda x: int(x) if x else 0)
    df['url_len'] = df['url_len'].map(lambda x: int(x) if x else 0)
    return df


def score_df(df):
    '''score based on parameters from training set'''
    df['alexa_result'] = df['alexa_rank'].map(lambda x: 1 if x > params.ALEXA_RANK_THRESH else 0)
    df['age_result'] = df['domain_age_days'].map(lambda x: 1 if x < params.DOMAIN_DAY_THRESH  else 0)
    df['host_len_res'] = df['host_len'].map(lambda x: 1 if x > params.HOST_LEN_THRESH else 0)
    df['file_ext_result'] = df['file_extension'].map(lambda x: 1 if x in params.FILE_EXT else 0)
    df['tld_result'] = df['tld'].map(lambda x: 1 if x in params.TLD else 0)
    df['ip_result'] = 0
    df['geo_result'] = 0
    df['domain_result'] = 0
    for idx,row in df.iterrows():
        try:
            for i in row['ips']:
                if i.get('ip') in params.IPS:
                    row['ip_result'] = 1
                if i.get('geo') in params.GEO:
                    row['geo_result'] = 1
            for i in row['domain_tokens']:
                if i in params.DOMAIN:
                    row['domain_result'] = 1
        except:
            pass
    df['total'] = df['alexa_result']+df['age_result']+df['host_len_res']+df['file_ext_result']+df['tld_result']+df['ip_result']+df['geo_result']+df['domain_result']
    df['malicious_url'] = df['total'].map(lambda x: 1 if x > 0 else 0)
    return df


def output_and_stats(df, output_file):
    '''print to CLI and save to CSV'''
    print("Total URLs Analyzed: {}".format(len(df)))
    print("Total Malicious URLs detected: {}".format(len(df.loc[df['malicious_url'] == 1])))
    df.to_csv(output_file)
    print("Results Saved at: {}".format(output_file))

def main():

    file = get_target_file()
    df = make_dataframe(file)
    df = clean_df(df)
    df = score_df(df)
    output_and_stats(df, file.split('.')[0]+"_out.csv")
    

if __name__ == "__main__":
    # main(sys.argv[1:])
    main()