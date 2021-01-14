import os
from .common import get_setting_value_by_name
from .common import set_setting_value_by_name

OVERRIDE_KDM = os.environ.get('RANCHER_OVERRIDE_KDM', "False")

def test_create_clusters_kdm():

    if OVERRIDE_KDM:
        get_rke_metadata_config()

def get_rke_metadata_config():
    rke_metadata_config = get_setting_value_by_name('rke_metadata_config')
    print(rke_metadata_config)
