from math import log
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
        labeled: Set to true only if logs contain labels
    """
    
    # HDFS Logs
    if log_source == 'HDFS':
        input_dir = 'Dataset/' + log_source
        log_format = '<Date> <Time> <Pid> <Level> <Component>: <Content>'
        regex      = [
            r'blk_(|-)[0-9]+' , # block id
            r'(/|)([0-9]+\.){3}[0-9]+(:[0-9]+|)(:|)', # IP
            r'(?<=[^A-Za-z0-9])(\-?\+?\d+)(?=[^A-Za-z0-9])|[0-9]+$', # Numbers
        ]    
    #Linux Logs        
    elif log_source == 'Linux':
        input_dir = 'Dataset/' + log_source
        log_format = '<Month> <Day> <Time> <Machine> <Task>: <Content>'
        regex      = [
            r'(/|)([0-9]+\.){3}[0-9]+(:[0-9]+|)(:|)', # IP
            r'(?<=[^A-Za-z0-9])(\-?\+?\d+)(?=[^A-Za-z0-9])|[0-9]+$', # Numbers
        ]        
    #Openstack Logs        
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

    if log_source == "Linux":
        #Sequence of all log keys
        np.savetxt(r'linux_sequences', df_log['Log Key'].values, fmt='%d', newline=' ')
    elif log_source == "HDFS":
        # If logs contain labels, extract normal and anomaly labels
        if labeled:
            norm_seq = {}
            abn_seq = {}

            labels = pd.read_csv("Dataset/HDFS/anomaly_label.csv").groupby("Label")
            normal_labels = labels.get_group("Normal")["BlockId"].values
            anomaly_labels = labels.get_group("Anomaly")["BlockId"].values
        # If no labels provided, all sequence will go in one file
        else:
            seqs = {}

        #Iterate through all parsed logs to create sequences
        for index, row in df_log.iterrows():
            # Get raw log content
            line= row['Content']

            if log_source == "HDFS":
                # Block ids are can be in two different formats
                if re.search("blk_-\d*", line):
                    seq_id = re.findall("blk_-\d*", line)[0]
                elif re.search("blk_\d*", line):
                    seq_id = re.findall("blk_\d*", line)[0]
                else:
                    print("Missing Block ID")
            elif log_source == "Linux":
                # Block ids are can be in two different formats
                if re.search("sshd\[(.*?)\]", line):
                    seq_id = re.findall("sshd\[(.*?)\]", line)[0]
                    print(seq_id)
                else:
                    continue

            # If logs contain labels, separate sequences into normal and anomaly
            # Currently only available for HDFS
            if labeled:
                if seq_id in normal_labels:
                    if seq_id in norm_seq:
                        norm_seq[seq_id].append(row['Log Key'])
                    else:
                        norm_seq[seq_id] = [row['Log Key']]
                if seq_id in anomaly_labels:
                    if seq_id in abn_seq:
                        abn_seq[seq_id].append(row['Log Key'])
                    else:
                        abn_seq[seq_id] = [row['Log Key']]                    
            else:
                # If sequence id is already in list, only update the sequence
                if seq_id in seqs:
                    seqs[seq_id].append(row['Log Key'])
                # Otherwise, create new sequence id                
                else:
                    seqs[seq_id] = [row['Log Key']]

        if labeled:
            output_seq(output_dir, log_source, norm_seq, abn_seq)
        else:
            output_seq(output_dir, log_source, seqs)


def output_seq(output_dir, log_source, seqs, abn_seq = ''):
    # If logs contain labels, places sequences into two separate files
    # for training
    if abn_seq:
        # Sequenced log keys
        with open(output_dir + log_source + '_normal', 'w') as f:
            for item in seqs:
                for log_key in seqs[item]:
                    f.write(str(log_key)+" ")
                f.write("\n")

        with open(output_dir + log_source + '_abnormal', 'w') as f:
            for item in abn_seq:
                for log_key in abn_seq[item]:
                    f.write(str(log_key)+" ")
                f.write("\n")
    else:
        with open(output_dir + 'seq_logs', 'w') as f:
            for item in seqs:
                for log_key in seqs[item]:
                    f.write(str(log_key)+" ")
                f.write("\n")

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