from __future__ import annotations
from abc import ABC, abstractmethod
import uuid
from helper.gsdml_parser import XMLDevice
from scapy.all import *
from scapy.contrib.pnio_rpc import *
from scapy.contrib.dce_rpc import *
from scapy.contrib.pnio import *
from states import *

load_contrib("pnio")
load_contrib("pnio_rpc")
load_contrib("dce_rpc")


class ProfiSafeHostContext:

    _state = None

    def __init__(
        self, state: PSState, crc1: int, dataLength: int, seed_zero: bool = True
    ) -> None:
        self.setState(state)
        self.crc1 = crc1
        self.dataLength = dataLength

        # VCN State (Consecutive Number)
        self.x = 0x0
        self.old_x = 0x0

        # assets
        self.oa_c_e = (
            0  # auxilary falg indicating a raising edge of the oa_c signal (0 -> 1)
        )
        self.oa_c = 0  # idk

        # Length of CRC
        self.crcLength = 3 if seed_zero else 4

        # Fail-Safe Bits are important if FV Status is currently active
        # important for inforamation if FailSafe Values are used
        # for now not that important
        self.activate_FV = 0
        self.activate_FV_S = 0  # Status Byte -> activate it
        self.FV_activated_S = 0  # -> is activated
        self.activate_FV_C = 0  # Control Byte
        self.FV_activated_C = 0  # Control Byte

        # parameter assignment
        self.ipar_ok_s = 0
        self.ipar_ok = 0

        # Control Byte Parameters
        self.ipar_en = 0  # iparameter assignment blocked (bit 0) (en = enabled)
        self.oa_req = 0  # Operator ACK Request, in case of fail state recovery (bit 1)
        self.r_cons_nr = 0  # reset vcn (bit 2)
        self.use_to2 = 0  # use secondary watchdog (bit 3)
        self.FV_activated = 0  # activate Fail-Safe Values (bit 4)
        self.toggle_h = 0  # toggle byte (bit 5)

        # Status Byte Parameters
        # only error cases are relenvant
        self.faults = {"Host_CE_CRC": False, "CE_CRC": False, "WD_timeout": False}
        self.i_par_ok_s = 0  # F-Device has new iParameter values assigned
        self.oa_req_s = (
            0  # varibale in F-Device which is 1 if failure occures until oa_c received
        )

        # that's important for watchdog but not important now
        self.host_timer = (
            None  # Here should be another lane defined in which the timer state works
        )
        self.lastStatus = None

        # pdu to send
        self.profisafe_block = None
        self.data = [0, 0, 0, 0, 0, 0, 0, 0]

    def setState(self, state: PSState):

        print(f"PROFISAFE: Transitioning to {type(state).__name__}")
        self._state = state
        self._state.context = self

    def getState(self):
        return self._state

    # State Methods
    # called every time Ack received
    def updateData(self, data) -> None:
        self._state.updateData(data)

    def timeout(self) -> None:
        self._state.timeout()

    def prepareMessage(self, data):
        self._state.prepareMessage(data)

    def setData(self, data):
        self.data = data[0 : self.dataLength]

    def getProfisafeBlock(self):
        return self.profisafe_block

    # Service Methods


class PSState(ABC):
    @property
    def context(self) -> ProfiSafeHostContext:
        return self._context

    @context.setter
    def context(self, context: ProfiSafeHostContext) -> None:
        self._context = context

    @abstractmethod
    def updateData(self, controlByte) -> None:
        pass

    @abstractmethod
    def prepareMessage(self, data):
        pass

    @abstractmethod
    def timeout(self):
        pass


class PNIOPSMessage:
    def __init__(self) -> None:
        self.cycle_counter = 0
        self.data_status = {
            "ignore": False,  # 1: Ignore 0: Evaluate
            "reserved_2": False,  # should be zero
            "station_problem_indicator": False,  # 1: Ok, 0: Problem
            "provider_state": False,  # 1: Run 0: Stop
            "reserved_1": False,  # should be zero
            "data_valid": False,  # 1: Valid, 0: Invalid
            "redundancy": False,  # has no meaning for outputCRs
            "state": False,  # 1: primary, 0. backup
        }
        self.input_data = {"iops": [], "iocs": [], "data": []}

    def convert_number_to_state_array(self, flags):
        self.data_status = {
            "ignore": flags.ignore,  # 1: Ignore 0: Evaluate
            "reserved_2": flags.reserved_2,  # should be zero
            "station_problem_indicator": flags.no_problem,  # 1: Ok, 0: Problem
            "provider_state": flags.run,  # 1: Run 0: Stop
            "reserved_1": flags.reserved_1,  # should be zero
            "data_valid": flags.validData,  # 1: Valid, 0: Invalid
            "redundancy": flags.redundancy,  # has no meaning for outputCRs
            "state": flags.primary,  # 1: primary, 0. backup
        }

    def bitarray_to_number(self, array):
        i = 0
        for bit in array:
            i = (i << 1) | bit
        return i

    def parse_io_state(self, state, slot, subslot):
        status_array = [int(digit) for digit in bin(state + 0x100)[2:]][1:]
        return {
            "module": str(slot),
            "submodule": str(subslot),
            "data_state": bool(status_array[0]),  # 1: Good 0: Bad
            "instance": self.bitarray_to_number(
                status_array[1:3]
            ),  # should be zero 0: Detected by subslot
            "reserved": self.bitarray_to_number(status_array[3:7]),  # should be zero
            "extension": bool(
                status_array[7]
            ),  # 0: No IOxS octet follows 1: IOxS octet follows
        }

    def parse_input_data(self, data, device):
        usable_modules = device.body.dap_list[0].usable_modules

        payload_bytes = list(data)

        first_iops = self.parse_io_state(payload_bytes[0], 0x1, 0x1)

        sec_iops = self.parse_io_state(payload_bytes[1], 0x1, 0x8000)

        thir_iops = self.parse_io_state(payload_bytes[2], 0x1, 0x8001)

        iops = [first_iops, sec_iops, thir_iops]
        iocs = []
        data = []

        output_frame_offset = 3

        for module in usable_modules:
            if module.used_in_slots != "" and module.output_length != 0:
                data.append(
                    payload_bytes[
                        output_frame_offset : (
                            output_frame_offset + module.output_length
                        )
                    ]
                )
                iops.append(
                    self.parse_io_state(
                        payload_bytes[output_frame_offset + module.output_length],
                        module.module_ident_number,
                        module.submodule_ident_number,
                    )
                )
                output_frame_offset += module.output_length + 1
        for module in usable_modules:
            if module.used_in_slots != "" and module.input_length != 0:
                iocs.append(
                    self.parse_io_state(
                        payload_bytes[output_frame_offset],
                        module.module_ident_number,
                        module.submodule_ident_number,
                    )
                )
                output_frame_offset += 1

        self.input_data = {"iops": iops, "iocs": iocs, "data": data}


def parse_data_message(packet, device):
    message = PNIOPSMessage()

    if packet.haslayer("PROFINET IO Real Time Cyclic Default Raw Data"):
        pkt_rt = packet.getlayer("PROFINET Real-Time")
        pkt_raw_layer = packet.getlayer("PROFINET IO Real Time Cyclic Default Raw Data")
        message.convert_number_to_state_array(pkt_rt.dataStatus)
        message.cycle_counter = pkt_rt.cycleCounter
        message.parse_input_data(pkt_raw_layer.data, device)

        return message

    else:
        return


def main():
    context = ProfiSafeHostContext(
        state=PrepareMessageInitState(), crc1=0x22FF, dataLength=8, seed_zero=True
    )

    context.prepareMessage("None")

    scapy_cap = rdpcap("./sniff/only_status_msgs.pcap")
    device = XMLDevice("./gsdml/test_project.xml")

    for packet in scapy_cap:
        pdu = bytearray(parse_data_message(packet, device).input_data["data"][0])
        context.updateData(pdu)
        time.sleep(1)


# time.sleep(20)

# context.connect()
# context.write("test")
# context.announceEndPrm()
# context.ackApplicationReady()


if __name__ == "__main__":
    main()
