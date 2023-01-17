import os
import pandas as pd

absolute_path = os.path.dirname(__file__)
DATAPATH = "data/csvs"

full_path = os.path.join(absolute_path, DATAPATH)

PATHS = {
    'deployer': os.path.join(full_path, "priority-options_v2.csv"),
    'impact': os.path.join(full_path, "ssvc_impact_options.csv"),
    'utility': os.path.join(full_path, "ssvc_utility_options.csv"),
}

DEFAULTS = {
    'deployer': {
        # An analyst should feel comfortable selecting none if they (or their search scripts) have performed searches
        # in the appropriate places for public PoCs and active exploitation (as described above) and found none.
        "Exploitation": "none",
        "Exposure": "unavoidable"
    },
    'impact': {
        "Environment": "none"
    },
    'utility': {
        "public_status": "none"
    }
}


def _load_csvs(path_dict):
    data = {}
    for key, path in path_dict.items():
        df = pd.read_csv(path)
        data[key] = df
    return data


DATA = _load_csvs(PATHS)

# confirm that PATHS and DATA keys match
assert (set(PATHS.keys()) == set(DATA.keys()))


def lookup(key, query_dict, use_defaults=True):
    # get the full table
    df = DATA[key]

    if use_defaults:
        # copy the defaults before we use them
        defaults = DEFAULTS.get(key, {})
        q = dict(defaults)
    else:
        q = {}

    q.update(query_dict)

    # with each pass, slice the table
    for k, v in q.items():
        df = df.loc[df[k] == v]
    return df


def outcome_dist(df, normalize=True):
    """
    Given a dataframe representing an SSVC tree fragment,
    compute and return the distribution of outcomes
    """
    return df['Priority'].value_counts(normalize=normalize)


def outcome_impact_dist(df, normalize=True):
    """
    Given a dataframe representing an SSVC tree fragment,
    compute and return the distribution of outcomes
    """
    return df['Impact'].value_counts(normalize=normalize)


def outcome_utility_dist(df, normalize=True):
    """
    Given a dataframe representing an SSVC tree fragment,
    compute and return the distribution of outcomes
    """
    return df['Utility'].value_counts(normalize=normalize)


def calculate_impact(query):
    for key, df in DATA.items():
        df = lookup('impact', query)
        return_recommednations = outcome_impact_dist(df).round(decimals=3).to_dict()
        return_recommednations = list(return_recommednations.keys())[0]
        return return_recommednations


def calculate_utility(query):
    for key, df in DATA.items():
        df = lookup('utility', query)
        return_recommednations = outcome_utility_dist(df).round(decimals=3).to_dict()
        return_recommednations = list(return_recommednations.keys())[0]
        return return_recommednations


def calculate_recommendation(query):
    for key, df in DATA.items():
        df = lookup('deployer', query)
        return_recommednations = outcome_dist(df).round(decimals=3).to_dict()
        return return_recommednations


def main(query):
    recommednation = calculate_recommendation(query)
    return recommednation


if __name__ == '__main__':
    main()
