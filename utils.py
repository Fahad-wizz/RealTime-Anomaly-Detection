import pandas as pd

def preprocess(df):
    df.fillna(0, inplace=True)
    return df