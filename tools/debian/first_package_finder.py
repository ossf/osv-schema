from urllib import request
from datetime import datetime
import gzip

import pandas as pd


def create_url(date: datetime, version: str = None):
    """Create an url for snapshot.debian.org"""
    base_url = 'https://snapshot.debian.org/archive/debian/{date}/dists/'
    # .gz format always exist for all snapshots
    source_path = '{version}/main/source/Sources.gz'

    formatted_date = convert_datetime_to_str_datetime(date)

    if version is None:
        # return url for retrieving all versions for date
        return base_url.format(date=formatted_date)
    else:
        return base_url.format(date=formatted_date) \
               + source_path.format(version=version)


def convert_datetime_to_str_datetime(input_datetime: datetime) -> str:
    """Convert datetime object to debian snapshot url string"""
    return input_datetime.isoformat().replace('-', '').replace(':', '') + 'Z'


def create_codename_to_version() -> pd.DataFrame:
    """Returns the codename to version mapping"""
    item = request.urlopen('https://debian.pages.debian.net/distro-info-data/debian.csv')
    df = pd.read_csv(item, dtype=str)
    # `series` appears to be `codename` but with no caps
    df['sources'] = ""
    df['first seen'] = ""
    codename_to_version = df.set_index('series')
    codename_to_version.loc['sid']['version'] = 'unstable'

    return codename_to_version


def parse_first_seen_dates(date: str) -> datetime:
    """Parse first seen date in debian table to datetime"""
    return datetime.strptime(date, "%Y-%m-%d %H:%M:%S")


def fillout_first_seen(date: datetime, first_seen_dict: dict[str, datetime]):
    """Fill out first seen version dict"""
    res = request.urlopen(create_url(date))
    # Pandas will try to convert every table on the webpage to a dataframe.
    # Select the first and only table
    df = pd.read_html(res.read())[0]
    # Select only directories
    df = df.loc[df.iloc[:, 0] == 'd']
    # Remove names that contain - since they are generally special versions of the main releases
    df: pd.DataFrame = df[(~df['Name'].str.contains('-'))]
    # Remove '/' from the directory names
    df['Name'] = df['Name'].map(lambda x: x.rstrip('/'))
    # Remove special parent directory
    df = df[df['Name'] != '..']
    # Convert first_seen date format to python datetime
    first_seen_mapped = df['first seen'].map(parse_first_seen_dates)
    first_seen_dict.update(zip(df['Name'], first_seen_mapped))


def load_sources(date: datetime, dist: str) -> dict[str, str]:
    """Load the sources file and store it in """
    res = request.urlopen(create_url(date, dist))
    decompressed = gzip.decompress(res.read()).decode('utf-8', errors='ignore')

    package_version_dict = dict()
    current_package = None
    for line in decompressed.splitlines():
        if line.startswith("Package: "):
            current_package = line.removeprefix("Package: ")
            continue

        if line.startswith("Version: "):
            package_version_dict[current_package] = line.removeprefix("Version: ")
            continue

    return package_version_dict


def load_first_packages() -> pd.DataFrame:
    """Loads the dataframe containing the first version of packages per distro"""

    codename_to_version: pd.DataFrame = create_codename_to_version()

    # 2005 is when first snapshot is taken
    search_date = datetime.fromisoformat('2005-12-01T00:00:00')
    first_seen_dict = dict()

    while search_date < datetime.today():
        fillout_first_seen(search_date, first_seen_dict)
        search_date = search_date.replace(year=search_date.year + 5)

    fillout_first_seen(search_date, first_seen_dict)

    for version, dates in first_seen_dict.items():
        codename_to_version.loc[version].sources = load_sources(dates, version)

    return codename_to_version


def get_first_package_version(first_pkg_data: pd.DataFrame, package_name: str, release_name: str) -> str:
    """Get first package version"""
    try:
        return first_pkg_data.loc[release_name].sources[package_name]
    except KeyError:
        print("Well...: " + package_name + "  " + release_name)
        return "0"


