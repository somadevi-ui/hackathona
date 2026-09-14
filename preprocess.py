"""
Preprocessing for NSL-KDD intrusion detection data.
Loads raw CSVs, encodes categorical fields, scales numeric fields,
and produces a binary label (normal=0 / attack=1) plus a readable
attack-category label for the demo dashboard.
"""

import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from columns import COLUMNS, ATTACK_CATEGORY

CATEGORICAL_COLS = ["protocol_type", "service", "flag"]


def load_raw(path):
    df = pd.read_csv(path, names=COLUMNS)
    # some NSL-KDD dumps have a trailing "difficulty" column with no header;
    # if column count doesn't match, trim extra column safely
    if df.shape[1] > len(COLUMNS):
        df = df.iloc[:, : len(COLUMNS)]
        df.columns = COLUMNS
    return df


def add_labels(df):
    df = df.copy()
    df["label"] = df["label"].str.strip()
    df["attack_category"] = df["label"].map(ATTACK_CATEGORY).fillna("unknown_attack")
    df["binary_label"] = (df["label"] != "normal").astype(int)
    return df


def fit_transform(train_df, test_df):
    """
    Fits encoders/scaler on training data, applies to both train and test.
    Returns X_train, X_test, y_train, y_test, plus fitted encoders and
    the original (readable) dataframes for reporting.
    """
    train_df = add_labels(train_df)
    test_df = add_labels(test_df)

    encoders = {}
    train_enc = train_df.copy()
    test_enc = test_df.copy()

    for col in CATEGORICAL_COLS:
        le = LabelEncoder()
        le.fit(pd.concat([train_df[col], test_df[col]], axis=0).astype(str))
        train_enc[col] = le.transform(train_df[col].astype(str))
        test_enc[col] = le.transform(test_df[col].astype(str))
        encoders[col] = le

    feature_cols = [c for c in COLUMNS if c != "label"]

    scaler = StandardScaler()
    X_train = scaler.fit_transform(train_enc[feature_cols])
    X_test = scaler.transform(test_enc[feature_cols])

    y_train = train_enc["binary_label"].values
    y_test = test_enc["binary_label"].values

    return {
        "X_train": X_train,
        "X_test": X_test,
        "y_train": y_train,
        "y_test": y_test,
        "feature_cols": feature_cols,
        "encoders": encoders,
        "scaler": scaler,
        "test_df_readable": test_df.reset_index(drop=True),  # for the live-feed demo
    }


if __name__ == "__main__":
    train = load_raw("data/KDDTrain.txt")
    test = load_raw("data/KDDTest.txt")
    bundle = fit_transform(train, test)
    print("Train shape:", bundle["X_train"].shape)
    print("Test shape:", bundle["X_test"].shape)
    print("Attack rate in test set:", bundle["y_test"].mean().round(3))
