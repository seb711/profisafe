from scapy.contrib.pnio import *
from scapy.all import *
from scapy.contrib.pnio_rpc import *
from scapy.contrib.dce_rpc import *
from scapy.contrib.pnio import *
import crcmod


load_contrib("pnio")
load_contrib("pnio_rpc")
load_contrib("dce_rpc")
crc2_func = crcmod.mkCrcFun(0x15D6DCB, initCrc=0, xorOut=0x0, rev=False)


def convert_controlbyte_to_dec(control_byte):
    return int(
        f'10{control_byte["Toggle_h"]}{control_byte["activate_FV"]}{control_byte["Use_TO2"]}{control_byte["R_cons_nr"]}{control_byte["OA_Req"]}{control_byte["iPar_EN"]}',
        2,
    )


def get_profisafe_pdu(control_byte, data, seed, vcn, crc_length=3):
    control_dec = convert_controlbyte_to_dec(control_byte)
    pdu = data + [control_dec]
    crc = crc2_func(
        bytearray([0x00] + list((vcn + 1).to_bytes(crc_length, "big")) + list(pdu))[::-1],
        crc=seed,
    )

    return PROFIsafeControl(data=data, control=control_dec, crc=crc)


def main():
    get_profisafe_pdu(
        control_byte={
            "Toggle_h": 1,
            "activate_FV": 1,
            "Use_TO2": 0,
            "R_cons_nr": 0,
            "OA_Req": 0,
            "iPar_EN": 0,
        },
        data=[0, 0, 0, 0, 0, 0, 0, 0],
        seed=0x22FF,
        vcn=1,
    ).show()


# time.sleep(20)

# context.connect()
# context.write("test")
# context.announceEndPrm()
# context.ackApplicationReady()


if __name__ == "__main__":
    main()
