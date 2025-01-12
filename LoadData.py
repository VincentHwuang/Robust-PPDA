import pandas as pd
import os
from glob import glob
from sklearn.model_selection import train_test_split
import torch
from torch.utils.data import Dataset, DataLoader
from PIL import Image
from torchvision import transforms
import numpy as np
import torchvision

# Custom dataset prepration in Pytorch format
class SkinData(Dataset):
    def __init__(self, df, transform = None):
        self.df = df
        self.transform = transform
        
    def __len__(self):
        
        return len(self.df)
    
    def __getitem__(self, index):
       
        X = Image.open(self.df['path'][index]).resize((64, 64))
        y = torch.tensor(int(self.df['target'][index]))
        
        if self.transform:
            X = self.transform(X)
        
        return X, y


def load_HAM10000_data(dataset_path, test_size = 0.2):
    df = pd.read_csv(dataset_path)
    print(df.head(10))

    # merging both folders of HAM1000 dataset -- part1 and part2 -- into a single directory
    imageid_path = {os.path.splitext(os.path.basename(x))[0]: x
                for x in glob(os.path.join("data", '*', '*.jpg'))}

    lesion_type = {
    'nv': 'Melanocytic nevi',
    'mel': 'Melanoma',
    'bkl': 'Benign keratosis-like lesions ',
    'bcc': 'Basal cell carcinoma',
    'akiec': 'Actinic keratoses',
    'vasc': 'Vascular lesions',
    'df': 'Dermatofibroma'
    }

    df['path'] = df['image_id'].map(imageid_path.get)
    df['cell_type'] = df['dx'].map(lesion_type.get)
    df['target'] = pd.Categorical(df['cell_type']).codes
    print(df['cell_type'].value_counts())
    print(df['target'].value_counts())

    # Train-test split    
    train, test = train_test_split(df, test_size = test_size)

    train = train.reset_index()
    test = test.reset_index()

    print(f'Number of training examples: {len(train)}')
    print(f'Number of testing examples: {len(test)}')

    # Data preprocessing: Transformation 
    mean = [0.485, 0.456, 0.406]
    std = [0.229, 0.224, 0.225]
    train_transforms = transforms.Compose([transforms.RandomHorizontalFlip(), 
                            transforms.RandomVerticalFlip(),
                            transforms.Pad(3),
                            transforms.RandomRotation(10),
                            transforms.CenterCrop(64),
                            transforms.ToTensor(), 
                            transforms.Normalize(mean = mean, std = std)
                            ])
        
    test_transforms = transforms.Compose([
                            transforms.Pad(3),
                            transforms.CenterCrop(64),
                            transforms.ToTensor(), 
                            transforms.Normalize(mean = mean, std = std)
                            ])    

    # image augmentation
    dataset_train = SkinData(train, transform = train_transforms)
    dataset_test = SkinData(test, transform = test_transforms)

    return dataset_train, dataset_test

def load_FMNIST_data(resize = None):
    trans = [transforms.ToTensor()]
    if resize:
        trans.insert(0, transforms.Resize(resize))
    trans = transforms.Compose(trans)
    mnist_train = torchvision.datasets.FashionMNIST(
        root="./data", train=True, transform=trans, download=False)
    mnist_test = torchvision.datasets.FashionMNIST(
        root="./data", train=False, transform=trans, download=False)
    return mnist_train, mnist_test

# dataset_iid() will create a dictionary to collect the indices of the data samples randomly for each client
# IID HAM10000 datasets will be created based on this
def dataset_iid(dataset, num_users):
    num_items = int(len(dataset)/num_users)
    dict_users, all_idxs = {}, [i for i in range(len(dataset))]
    for i in range(num_users):
        dict_users[i] = set(np.random.choice(all_idxs, num_items, replace = False))
        all_idxs = list(set(all_idxs) - dict_users[i])
    return dict_users    
