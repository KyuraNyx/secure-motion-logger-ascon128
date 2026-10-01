import machine

class MPU6050:
    """
    MicroPython driver for the MPU-6050 6-DoF Accelerometer and Gyroscope.
    Communicates via I2C / SoftI2C at default address 0x68.
    """

    def __init__(self, i2c, addr=0x68):
        self.iic = i2c
        self.addr = addr
        try:
            # Wake up MPU-6050 (write 0 to Power Management 1 register 0x6B)
            self.iic.writeto_mem(self.addr, 0x6B, b'\x00')
        except OSError:
            print("[ERROR] MPU-6050: Failed to communicate. Check SDA/SCL wiring!")

    def get_raw_values(self):
        """Read 14 contiguous data bytes starting at register 0x3B."""
        return self.iic.readfrom_mem(self.addr, 0x3B, 14)

    def bytes_toint(self, firstbyte, secondbyte):
        """Convert two 8-bit bytes into a signed 16-bit integer."""
        if not firstbyte & 0x80:
            return firstbyte << 8 | secondbyte
        return - (((firstbyte ^ 255) << 8) | (secondbyte ^ 255) + 1)

    def get_values(self):
        """
        Return parsed sensor readings in engineering units:
        AcX, AcY, AcZ: Raw 16-bit accelerometer readings
        Tmp: Temperature in degrees Celsius
        GyX, GyY, GyZ: Raw 16-bit gyroscope readings
        """
        raw_ints = self.get_raw_values()
        vals = {}
        vals["AcX"] = self.bytes_toint(raw_ints[0], raw_ints[1])
        vals["AcY"] = self.bytes_toint(raw_ints[2], raw_ints[3])
        vals["AcZ"] = self.bytes_toint(raw_ints[4], raw_ints[5])
        vals["Tmp"] = self.bytes_toint(raw_ints[6], raw_ints[7]) / 340.00 + 36.53
        vals["GyX"] = self.bytes_toint(raw_ints[8], raw_ints[9])
        vals["GyY"] = self.bytes_toint(raw_ints[10], raw_ints[11])
        vals["GyZ"] = self.bytes_toint(raw_ints[12], raw_ints[13])
        return vals
