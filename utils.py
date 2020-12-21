import sys
sys.path.append('../')
import os
import pandas as pd
import numpy as np
import importlib
import re

from Parsers import Drain
from Parsers import Spell

importlib.reload(Spell)
importlib.reload(Drain)

def parse(log_source, log_file, algorithm, labeled = 'False', start_date = '', start_time = '', end_date = '', end_time = ''):
    """
    Parses log file.

    Args:
        log_source: The source of the logs (e.g. HDFS, Openstack, Linux).
        log_file: The name of the log file.
        algorithm: Parsing algorithm: Spell or Drain.
        
    """

    if log_source == 'HDFS':
        input_dir = 'Dataset/' + log_source
        log_format = '<Date> <Time> <Pid> <Level> <Component>: <Content>'
        regex      = [
            r'blk_(|-)[0-9]+' , # block id
            r'(/|)([0-9]+\.){3}[0-9]+(:[0-9]+|)(:|)', # IP
            r'(?<=[^A-Za-z0-9])(\-?\+?\d+)(?=[^A-Za-z0-9])|[0-9]+$', # Numbers
        ]    
    elif log_source == 'Linux':
        print("Parse linux logs")
    elif log_source == 'Openstack':
        print("Parse Openstack logs")

    if algorithm == 'Spell':
        output_dir = 'Spell_result/' # The output directory of parsing results
        tau        = 0.6 # Message type threshold (default: 0.5)
        parser = Spell.LogParser(indir=input_dir, outdir=output_dir, log_format=log_format, tau=tau, rex=regex)
        parsed_logs = parser.parse(log_file)
    elif algorithm == 'Drain':
        output_dir = 'Drain_result/' # The output directory of parsing results
        st         = 0.5 # Similarity threshold
        depth      = 4 # Depth of all leaf nodes
        parser = Drain.LogParser(log_format, indir=input_dir, outdir=output_dir, depth=depth, st=st, rex=regex)
        parsed_logs = parser.parse(log_file)

    seq(parsed_logs, output_dir, log_source, labeled)

def seq(df_log, output_dir, log_source, labeled):

    if labeled:
        a_blk_ids = {}
        n_blk_ids = {}

        labels = pd.read_csv("Dataset/HDFS/anomaly_label.csv").groupby("Label")
        normal_labels = labels.get_group("Normal")["BlockId"].values
        anomaly_labels = labels.get_group("Anomaly")["BlockId"].values
    else:
        blk_ids = {}

    for index, row in df_log.iterrows():
        # Get raw log content
        line= row['Content']

        # Block ids are can be in two different formats
        if re.search("blk_-\d*", line):
            blk_id = re.findall("blk_-\d*", line)[0]
        elif re.search("blk_\d*", line):
            blk_id = re.findall("blk_\d*", line)[0]
        else:
            print("Missing Block ID")

        if labeled:
            if blk_id in normal_labels:
                if blk_id in n_blk_ids:
                    n_blk_ids[blk_id].append(row['Log Key'])
                else:
                    n_blk_ids[blk_id] = [row['Log Key']]
            if blk_id in anomaly_labels:
                if blk_id in a_blk_ids:
                    a_blk_ids[blk_id].append(row['Log Key'])
                else:
                    a_blk_ids[blk_id] = [row['Log Key']]
        else:
            if blk_id in blk_ids:
                blk_ids[blk_id].append(row['Log Key'])
            else:
                blk_ids[blk_id] = [row['Log Key']]

    if labeled:
        # Sequenced log keys
        with open(output_dir + log_source + '_normal', 'w') as f:
            for item in n_blk_ids:
                for log_key in n_blk_ids[item]:
                    f.write(str(log_key)+" ")
                f.write("\n")

        with open(output_dir + log_source + '_abnormal', 'w') as f:
            for item in a_blk_ids:
                for log_key in a_blk_ids[item]:
                    f.write(str(log_key)+" ")
                f.write("\n")
    else:
        with open(output_dir + 'seq_logs', 'w') as f:
            for item in blk_ids:
                for log_key in blk_ids[item]:
                    f.write(str(log_key)+" ")
                f.write("\n")

    #Sequence of all log keys
    np.savetxt(r'log_keys', df_log['Log Key'].values, fmt='%d', newline=' ')


def backtrace(pred, log_source, algorithm):
    """
    Find log templates from sequence of log keys.

    Args:
        pred: The sequence of log keys.
        log_source: The source of the log keys.
        algorithm: Parsing algorithm: Spell or Drain.
    """
    log_template = pd.read_csv(algorithm + "_result/" + log_source + "_templates.csv") 
    y = np.squeeze(pred.tolist())
    for log in y:
        if log == -1: continue
        print(log, log_template['EventTemplate'][log-1])