// Display connections
#define LCD_RST     0x04 // GPIO port B bit2
#define LCD_E       0x08 // GPIO port B bit3
#define LCD_RW      0x20 // GPIO port B bit5
#define LCD_A0      0x40 // GPIO port B bit6
#define LCD_CS      0x80 // GPIO port B bit7

// Display commands
#define CMD_DISP_ON             0xAF // bit0 = 1 - On; bit0 = 0 - Off
#define CMD_DISP_OFF            0xAE // bit0 = 1 - On; bit0 = 0 - Off
#define CMD_DISP_LINE_ADDR      0x40 // bits 5..0 = line address 63..0
#define CMD_DISP_PAGE_ADDR      0xB0 // bits 3..0 = Page Address
#define CMD_DISP_COLADDR_H      0x10 // bits3..0 = column address high nibble
#define CMD_DISP_COLADDR_L      0x00 // bits3..0 = column address low nibble
#define CMD_DISP_REV            0xC0 // bit3 = 0 normal column direction, bit3 = 1 reverse column direction
#define CMD_DISP_INV            0xC6 // bit0 = 1 RAM data = 1 - LCD pixel = ON
                                     // bit0 = 0 RAM data = 1 - LCD pixel = OFF
#define CMD_DISP_ALL_ON         0xC4 // bit0 = 1 - all pixels ON, bit0 = 0 - normal operation
                                     // Executing this command when display Off = Power Save Mode
#define CMD_DISP_SET_BIAS       0xA2 // bit0 = 0 - 1/9 bias, bit0 = 1 - 1/7 bias
#define CMD_DISP_RESET          0x71 // Reset command
#define CMD_DISP_SCANDIR        0xA0 // bit3 = 0 - normal row scan direction (COM0->COM63)
                                     // bit3 = 1 - reversed row scan direction (COM63->COM0), bits 2..0 don't care
#define CMD_DISP_PWRCTRL        0x28 // bit0 - LCD Voltage Follower ON/OFF
                                     // bit1 - LCD Voltage Regulator ON/OFF
                                     // bit2 - LCD Voltage Converter ON/OFF
#define LCD_VFOL 0x01
#define LCD_VREG 0x02
#define LCD_VCNV 0x04

#define CMD_DISP_VREG_RES_RATIO 0x20 // bits3..0 - LCD Voltage Regulator Resistor Ratio
#define CMD_DISP_EVOLUME_MODE   0x81 // Enables Electronic Volume Control Register
                                     // for contrast control.
#define LCD_EVOLUME_VALUE  0x17      // Default value for contrast register
