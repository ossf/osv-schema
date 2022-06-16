"""Functions to help find the first package version for a specific release"""

from urllib import request
from datetime import datetime
import gzip

import pandas as pd

DEBIAN_RELEASE_VERSIONS_URL = 'https://debian.pages.debian.net/distro-info-data/debian.csv'

def create_url(date: datetime, version: str = None):
  """Create an url for snapshot.debian.org"""
  base_url = 'https://snapshot.debian.org/archive/debian/{date}/dists/'
  # `.gz` format always exist for all snapshots
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
  with request.urlopen(DEBIAN_RELEASE_VERSIONS_URL) as csv:
    df = pd.read_csv(csv, dtype=str)
    # `series` appears to be `codename` but with no caps
    df['sources'] = ''
    df['first seen'] = ''
    codename_to_version = df.set_index('series')
    codename_to_version.loc['sid']['version'] = 'unstable'

  return codename_to_version


def parse_first_seen_dates(date: str) -> datetime:
  """Parse first seen date in debian table to datetime"""
  return datetime.strptime(date, '%Y-%m-%d %H:%M:%S')


def fillout_first_seen(date: datetime, first_seen_dict: dict[str, datetime]):
  """Fill out first seen version dict"""
  with request.urlopen(create_url(date)) as result:
    # Pandas will try to convert every table on the webpage to a dataframe.
    # Select the first and only table
    df = pd.read_html(result.read())[0]
    # Select only directories
    df = df.loc[df.iloc[:, 0] == 'd']
    # Remove names that contain - since they are generally
    # special versions of the main releases
    df: pd.DataFrame = df[(~df['Name'].str.contains('-'))]
    # Remove '/' from the directory names
    df['Name'] = df['Name'].map(lambda x: x.rstrip('/'))
    # Remove special parent directory
    df = df[df['Name'] != '..']
    # Convert first_seen date format to python datetime
    first_seen_mapped = df['first seen'].map(parse_first_seen_dates)
    first_seen_dict.update(zip(df['Name'], first_seen_mapped))


def load_sources(date: datetime, dist: str) -> dict[str, str]:
  """Load the sources file and store in a dictionary of {name: version}"""
  with request.urlopen(create_url(date, dist)) as res:
    decompressed = gzip.decompress(res.read()).decode('utf-8', errors='ignore')
    package_version_dict = {}
    current_package = None
    for line in decompressed.splitlines():
      if line.startswith('Package: '):
        current_package = line.removeprefix('Package: ')
        continue

      if line.startswith('Version: '):
        package_version_dict[current_package] = line.removeprefix('Version: ')
        continue

    return package_version_dict


def load_first_packages() -> pd.DataFrame:
  """Loads the dataframe containing the first version of packages per distro"""

  codename_to_version: pd.DataFrame = create_codename_to_version()

  # 2005 is when first snapshot is taken
  search_date = datetime.fromisoformat('2005-12-01T00:00:00')
  first_seen_dict = {}

  while search_date < datetime.today():
    fillout_first_seen(search_date, first_seen_dict)
    # Increments of 5 years will not skip any version
    search_date = search_date.replace(year=search_date.year + 5)

  # Search date is in the future, so debian will select the latest snapshot
  fillout_first_seen(search_date, first_seen_dict)

  for version, dates in first_seen_dict.items():
    codename_to_version.loc[version].sources = load_sources(dates, version)

  return codename_to_version


def get_first_package_version(first_pkg_data: pd.DataFrame, package_name: str,
                              release_name: str) -> str:
  """Get first package version"""
  try:
    return first_pkg_data.loc[release_name].sources[package_name]
  except KeyError:
    # The package is not added when the image is first seen.
    # So it is safe to return 0, indicating the earliest version
    # given by the snapshot API
    return '0'


def main():
  dataframe = load_first_packages()
  print(dataframe)
  dataframe.to_pickle('first_package_cache.pickle.gz', compression='gzip')


if __name__ == '__main__':
  main()
