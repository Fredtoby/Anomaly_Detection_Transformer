import argparse
import Transformer as tnsf

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('--log_file', default='HDFS/hdfs_train', type=str, help='parsed log file')
    parser.add_argument('--batch_size', default=100, type=int, help='input batch size for training')
    parser.add_argument('--epochs', default=100, type=int, help='number of epochs to train')
    parser.add_argument('--window_size', default=10, type=int, help='lenght of training window')
    parser.add_argument('--hidden_size', default=1024, type=int, help='hidden size layer')
    parser.add_argument('--num_layers', default=4, type=int, help='number of encoder and decoders')
    parser.add_argument('--num_heads', default=4, type=int, help='number of heads')
    parser.add_argument('--seed', default=1, type=int, help='random seed')

    parser.add_argument('--num_classes', type=int, help='number of total log keys')
    parser.add_argument('--num_candidates', default=10, type=int, help='number of predictors sequence as correct predict')
    
    parser.add_argument('--num_gpus', default=0, type=int, help='number of gpus of gpus to train')
    parser.add_argument('--model_dir', default='Model/', type=str, help='the directory to store the model')
    parser.add_argument('--data_dir', default='Dataset/', type=str, help='the directory where training data is stored')
    
    args = parser.parse_args()

    tnsf.train(args)

def epoch_time(start_time: int, end_time: int):
    elapsed_time = end_time - start_time
    elapsed_mins = int(elapsed_time / 60)
    elapsed_secs = int(elapsed_time - (elapsed_mins * 60))
    return elapsed_mins, elapsed_secs    