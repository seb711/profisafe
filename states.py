from context import PSState
import crcmod

from messages.pnio_safe import get_profisafe_pdu

crc2_func = crcmod.mkCrcFun(0x15D6DCB, initCrc=0, xorOut=0x0, rev=False)


def extractStatusByteData(statusByte):
    binaryRep = "{0:08b}".format(statusByte)
    statusObj = {
        "Bit7": 1 if int(binaryRep[0]) == 1 else 0,
        "cons_nr_R": 1 if int(binaryRep[1]) == 1 else 0,
        "Toggle_d": 1 if int(binaryRep[2]) == 1 else 0,
        "FV_activated": 1 if int(binaryRep[3]) == 1 else 0,
        "WD_timeout": 1 if int(binaryRep[4]) == 1 else 0,
        "CE_CRC": 1 if int(binaryRep[5]) == 1 else 0,
        "Device_Fault": 1 if int(binaryRep[6]) == 1 else 0,
        "iPar_OK": 1 if int(binaryRep[7]) == 1 else 0,
    }

    return statusObj


def isDeviceFault(faults):
    return faults["Host_CE_CRC"] or faults["CE_CRC"] or faults["WD_timeout"]


def checkCRC(data, crcLength, crc1, vcn):
    # print(
    #     crcLength,
    #     list(data[: (crcLength * -1)]),
    #     list(vcn.to_bytes(crcLength, "big")),
    # )
    # print(
    #     "[checkCRC]",
    #     hex(
    #         crc2_func(
    #             bytearray(
    #                 [0x00]
    #                 + list(vcn.to_bytes(crcLength, "big"))
    #                 + list(data[: (crcLength * -1)])
    #             )[::-1],
    #             crc=crc1,
    #         )
    #     ),
    #     hex(int.from_bytes(bytes(data[(crcLength * -1) :]), "big")),
    #     vcn,
    # )
    if (
        hex(
            crc2_func(
                bytearray(
                    [0x00]
                    + list(vcn.to_bytes(crcLength, "big"))
                    + list(data[: (crcLength * -1)])
                )[::-1],
                crc=crc1,
            )
        )
        == hex(int.from_bytes(bytes(data[(crcLength * -1) :]), "big"))
    ):
        return True
    else:
        return False


# Preparation of a regular safety PDU for the F-Device
class PrepareMessageInitState(PSState):
    def updateData(self, data) -> None:
        # TODO what is to do in the init
        return

    def prepareMessage(self, data):
        # TODO write build message method in scapy in pnio_safe.py

        # Use Fail-Safe Values
        context = self.context
        context.activate_FV = 1
        context.FV_activated_S = 1

        # Toggle Bit
        context.toggle_h = 1

        profisafe_block = get_profisafe_pdu(
            control_byte={
                "Toggle_h": self.context.toggle_h,
                "activate_FV": self.context.activate_FV,
                "Use_TO2": self.context.use_to2,
                "R_cons_nr": self.context.r_cons_nr,
                "OA_Req": self.context.oa_req,
                "iPar_EN": self.context.ipar_en,
            },
            data=[0,0,0,0, 0, 0, 0, 0],
            seed=0x22FF,
            vcn=self.context.x,
        )

        profisafe_block.show()

        self.context.setState(AwaitDeviceInitAckState())
        return

    def timeout(self):
        return


# Preparation of a safety PDU for the F-Device (exception handling)
class PrepareMessageFaultState(PSState):
    def updateData(self, data) -> None:
        return

    def prepareMessage(self, data):
        # TODO craft message -> no more things to do except sending message

        profisafe_block = get_profisafe_pdu(
            control_byte={
                "Toggle_h": self.context.toggle_h,
                "activate_FV": self.context.activate_FV,
                "Use_TO2": self.context.use_to2,
                "R_cons_nr": self.context.r_cons_nr,
                "OA_Req": self.context.oa_req,
                "iPar_EN": self.context.ipar_en,
            },
            data=[0xC3, 0x7E, 0, 0xFF, 0, 0, 0, 0],
            seed=0x22FF,
            vcn=self.context.x,
        )

        profisafe_block.show()

        self.context.setState(AwaitDeviceFaultAckState())
        return

    def timeout(self):
        return


# Preparation of a regular safety PDU for the F-Device
class PrepareMessageNoFaultState(PSState):
    def updateData(self, data) -> None:
        return

    def prepareMessage(self, data):
        # TODO craft message -> no more things to do except sending message
        profisafe_block = get_profisafe_pdu(
            control_byte={
                "Toggle_h": self.context.toggle_h,
                "activate_FV": self.context.activate_FV,
                "Use_TO2": self.context.use_to2,
                "R_cons_nr": self.context.r_cons_nr,
                "OA_Req": self.context.oa_req,
                "iPar_EN": self.context.ipar_en,
            },
            data=[0xC3, 0x7E, 0, 0xFF, 0, 0, 0, 0],
            seed=0x22FF,
            vcn=self.context.x,
        )

        profisafe_block.show()

        self.context.setState(AwaitDeviceNoFaultAckState())
        return

    def timeout(self):
        return


# Safety Layer is waiting on next regular safety PDU from F-Device (Acknoledgement)
class AwaitDeviceInitAckState(PSState):
    def updateData(self, data) -> None:
        extractedControlByte = extractStatusByteData(data[-4])
        self.context.lastStatus = (
            extractedControlByte  # update data in global context state
        )
        if extractedControlByte["CE_CRC"]:
            self.context.faults["CE_CRC"] = True

        if extractedControlByte["WD_timeout"]:
            self.context.faults["WD_timeout"] = True
        if (
            extractedControlByte["Toggle_d"] == 1
            and extractedControlByte["cons_nr_R"] == self.context.r_cons_nr
        ):
            # T3
            self.context.setState(CheckDeviceAckToggleEqState())
            self.context.updateData(data)
        return

    def timeout(self):
        # t10
        # TODO restart timer
        # TODO store faults -> where do we get the faults at timeout ?

        # reset whole process -> vcn ...
        self.context.activate_FV = 1
        self.context.FV_activated_S = 1
        self.context.toggle_h = 1 - self.context.toggle_h
        self.context.r_cons_nr = 1
        self.context.x = 0
        self.context.setState(PrepareMessageFaultState())
        return self.context.prepareMessage(None)

    def prepareMessage(self, data):
        # in this case nothing happens -> timeout should set the state to prepareMessage if so
        return


# Safety Layer is waiting on next irregular safety PDU from F-Device (Acknoledgement)
class AwaitDeviceNoFaultAckState(PSState):
    def updateData(self, data) -> None:
        extractedControlByte = extractStatusByteData(data[-4])
        self.context.lastStatus = (
            extractedControlByte  # update data in global context state
        )
        if extractedControlByte["CE_CRC"]:
            self.context.faults["CE_CRC"] = True

        if extractedControlByte["WD_timeout"]:
            self.context.faults["WD_timeout"] = True
        if extractedControlByte["Toggle_d"] != self.context.toggle_h:
            # T7
            self.context.setState(CheckDeviceAckToggleNotEqState())
            # TODO call checkdata
            # nothing to do
            return self.context.updateData(data)
        else:
            # T6
            self.context.setState(CheckDeviceAckToggleEqState())
            # TODO restart host-timer
            return self.context.updateData(data)

    def timeout(self):
        # T12
        # TODO restart timer
        # TODO store faults -> where do we get the faults at timeout ?

        # reset whole process and use FailSafe Values
        self.context.activate_FV = 1
        self.context.FV_activated_S = 1
        self.context.toggle_h = 1 - self.context.toggle_h
        self.context.r_cons_nr = 1
        self.context.x = 0
        self.context.setState(WaitDelayTimeState())
        return self.context.timeout()

    def prepareMessage(self, data):
        return


# Safety Layer is waiting on next regular safety PDU from F-Device (Acknoledgement)
class AwaitDeviceFaultAckState(PSState):
    def updateData(self, data) -> None:
        extractedControlByte = extractStatusByteData(data[-4])
        self.context.lastStatus = (
            extractedControlByte  # update data in global context state
        )
        if extractedControlByte["CE_CRC"]:
            self.context.faults["CE_CRC"] = True

        if extractedControlByte["WD_timeout"]:
            self.context.faults["WD_timeout"] = True

        if (
            extractedControlByte["Toggle_d"] == self.context.toggle_h
            and extractedControlByte["cons_nr_R"] == self.context.r_cons_nr
        ):
            # T16
            self.context.setState(CheckDeviceAckFaultState())
            return self.context.updateData(data)

    def timeout(self):
        # T20
        # reset whole process
        self.context.oa_req = 0  # operator ack request
        self.context.oa_req_s = 0  # idk
        self.context.oa_c_e = 0  # idk

        # use FailSafe Values
        self.context.activate_FV = 1
        self.context.FV_activated_S = 1
        self.context.toggle_h = 1 - self.context.toggle_h
        self.context.r_cons_nr = 1
        self.context.x = 0

        # TODO restart timer
        self.context.setState(PrepareMessageFaultState())
        return self.context.prepareMessage()

    def prepareMessage(self, data):
        return


# Check received safety PDU for a CRC-error (Host_CE_CRC) including
# virtual consecutive number (x) and for potential
# F-Device faults within the Status Byte (WD_timeout, CE_CRC)
class CheckDeviceAckToggleEqState(PSState):
    def updateData(self, data) -> None:
        # TODO Check CRC of input data
        # TODO store faults from status byte
        if not checkCRC(
            data, self.context.dataLength, self.context.crc1, self.context.x + 1
        ):
            self.context.faults["Host_CE_CRC"] = True
        # TODO
        if not isDeviceFault(self.context.faults):
            self.context.old_x = self.context.x
            self.context.x += 1
            if self.context.x == 0x1000000:
                self.context.x = 1
            self.context.toggle_h = 1 - self.context.toggle_h

            if (
                self.context.activate_FV_C
                or self.context.FV_activated
                or isDeviceFault(self.context.faults)
            ):
                self.context.FV_activated_S = 1  # use failsafe input values
            else:
                self.context.FV_activated_S = 0  # do not use failsafe input values

            if self.context.activate_FV_C or isDeviceFault(self.context.faults):
                self.context.activate_FV = 1  # use failsafe outputs
            else:
                self.context.activate_FV = 0  # do not use failsafe outputs

            self.context.ipar_ok_s = self.context.ipar_ok

            self.context.setState(PrepareMessageNoFaultState())
            return self.context.prepareMessage(data)

        else:
            # T11
            # reset whole process -> vcn ...
            # use Failsafe Values -> activate failsafe mode
            self.context.activate_FV = 1
            self.context.FV_activated_S = 1

            self.context.toggle_h = 1 - self.context.toggle_h
            self.context.r_cons_nr = 1
            self.context.x = 0

            if checkCRC(
                data, self.context.dataLength, self.context.crc1, self.context.x
            ):
                self.context.faults["Host_CE_CRC"] = True

            self.context.setState(PrepareMessageFaultState())
            return self.context.prepareMessage(data)

    def timeout(self):
        # here does nothing happen
        return

    def prepareMessage(self, data):
        # here does nothing happen
        return


# Check received safety PDU for a CRC-error (Host_CE_CRC) including
# previous virtual consecutive number (old_x) and for potential
# F-Device faults within the Status Byte (WD_timeout, CE_CRC)
class CheckDeviceAckToggleNotEqState(PSState):
    # TODO Check CRC of input data

    def updateData(self, data) -> None:
        if not checkCRC(data, self.context.dataLength, self.context.crc1, self.context.x):
            self.context.faults["Host_CE_CRC"] = True
        if not isDeviceFault(self.context.faults):
            # T8
            # No Update of VCN!!!
            if (
                self.context.activate_FV_C
                or self.context.FV_activated
                or isDeviceFault(self.context.faults)
            ):
                self.context.FV_activated_S = 1  # use failsafe input values
            else:
                self.context.FV_activated_S = 0  # do not use failsafe input values

            if self.context.activate_FV_C or isDeviceFault(self.context.faults):
                self.context.activate_FV = 1  # use failsafe outputs
            else:
                self.context.activate_FV = 0  # do not use failsafe outputs

            self.context.ipar_ok_s = self.context.ipar_ok

            self.context.setState(PrepareMessageNoFaultState())
            return self.context.prepareMessage(data)
        else:
            # T14
            # TODO restart host-timer
            # TODO store faults
            # Use FailSafe Values
            self.context.activate_FV = 1
            self.context.FV_activated_S = 1
            self.context.toggle_h = 1 - self.context.toggle_h
            self.context.r_cons_nr = 1
            self.context.x = 0

            self.context.setState(PrepareMessageFaultState())
            return self.context.prepareMessage(data)

    def timeout(self):
        return

    def prepareMessage(self, data):
        # nothing to do here
        return


# Check received safety PDU for a CRC-error (Host_CE_CRC) including virtual consecutive
# number (x) and for potential F-Device faults within the Status Byte (WD_timeout, CE_CRC)
# Once a fault occurred, no automatic restart of a safety function is permitted unless
# an operator achnowledgement signal (oa_c) arrived
class CheckDeviceAckFaultState(PSState):
    def updateData(self, data) -> None:
        # TODO Check CRC of input data
        if not checkCRC(
            data, self.context.dataLength, self.context.crc1, self.context.x + 1
        ):
            self.context.faults["Host_CE_CRC"] = True

        if (
            not isDeviceFault(self.context.faults)
            and self.context.oa_c_e
            and self.context.oa_c
        ):
            # T17
            # reset stored faults
            self.context.faults = {
                "Host_CE_CRC": False,
                "CE_CRC": False,
                "WD_timeout": False,
            }

            # reset operator ack flags
            self.context.oa_req_s = 0
            self.context.oa_req = 0
            self.context.oa_c_e = 0

            # reset vcn
            self.context.r_cons_nr = 0
            self.context.old_x = self.context.x
            self.context.x += 1
            if self.context.x == 0x1000000:
                self.context.x = 1
            self.context.toggle_h = 1 - self.context.toggle_h

            if (
                self.context.activate_FV_C
                or self.context.FV_activated
                or not isDeviceFault(self.context.faults)
            ):
                self.context.FV_activated_S = 1  # use failsafe input values
            else:
                self.context.FV_activated_S = 0  # do not use failsafe input values

            if self.context.activate_FV_C or isDeviceFault(self.context.faults):
                self.context.activate_FV = 1  # use failsafe outputs
            else:
                self.context.activate_FV = 0  # do not use failsafe outputs

            self.context.ipar_ok_s = self.context.ipar_ok

            self.context.setState(PrepareMessageNoFaultState())
            return self.prepareMessage(data)
        elif isDeviceFault(self.context.faults):
            # T18
            # TODO store faults
            # reset operator ack flags
            self.context.oa_req_s = 0
            self.context.oa_req = 0
            self.context.oa_c_e = 0
            # Use FailSafe Values
            self.context.activate_FV = 1
            self.context.FV_activated_S = 1
            self.context.toggle_h = 1 - self.context.toggle_h
            self.context.r_cons_nr = 1
            self.context.x = 0

            self.context.setState(PrepareMessageFaultState())
            return self.prepareMessage(data)
        elif (
            not isDeviceFault(self.context.faults)
            and not self.context.oa_c
            and not self.context.oa_c_e
        ):
            # T19
            # operator ack request to reset
            self.context.oa_req_s = 1
            self.context.oa_req = 1
            if self.context.oa_c == 0:
                self.context.oa_c_e = 1
            # use failsafe values
            self.context.activate_FV = 1
            self.context.FV_activated_S = 1
            self.context.toggle_h = 1 - self.context.toggle_h
            self.context.r_cons_nr = 0
            self.context.old_x = self.context.x
            self.context.x += 1
            if self.context.x == 0x1000000:
                self.context.x = 1
            self.context.setState(PrepareMessageFaultState())
            return self.prepareMessage(data)

    def timeout(self):
        return

    def prepareMessage(self, data):
        return


# This state to avoid the storage of a timeout fault in case of an occastional system shotdown
# which would cause a request for an operator acknowledge with the next power-on. A delay time of 0ms is
# permitted
class WaitDelayTimeState(PSState):
    def updateData(self, controlByte) -> None:
        return

    def timeout(self):
        # T13
        # TODO Timeout of machine
        self.context.setState(PrepareMessageFaultState())
        return self.context.prepareMessage(None)

    def prepareMessage(self, data):
        return
