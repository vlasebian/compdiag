import os

from compdiag.main import Compdiag

HUE_BLE_PCAP_DIR = '/home/vlasebian/compdiag/pcaps/hue-ble/'
DS4_BLE_PCAP_DIR = '/home/vlasebian/compdiag/pcaps/ds4-ble/'

DIRECTORIES = [
        HUE_BLE_PCAP_DIR,
        DS4_BLE_PCAP_DIR,
    ]

def main():
    for dirr in DIRECTORIES:
        # Generate only from packet captures
        filenames = filter(
                lambda filename:
                    filename.endswith('.pcap') or
                    filename.endswith('.pcapng'),
                os.listdir(dirr))

        for filename in filenames:
            if 'btsmp' in filename:
                continue

            print('Generating diagram from ' + dirr + filename + '...')
            Compdiag.build_diagram(dirr + filename, 'ble', dirr + filename)

if __name__ == '__main__':
    main()

