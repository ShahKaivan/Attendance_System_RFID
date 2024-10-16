# IoTBasedAttendanceSystem-RFID-

### This project scans a RFID card, reads card’s data and sends data to Google sheet along with date and time at which card is scanned.


Components used: 
1] NodeMcu 1.0
2] RFID-RC522 Module 
3] Bread Board & Jumper wires 
4] Buzzer

Working: 
1] When the tag is brought close to the reader, the reader generates an electromagnetic field. This causes electrons to move through the tag’s antenna and subsequently powers the chip.
The chip then responds by sending its stored information back to the reader in the form of another radio signal. This is called a backscatter. The reader detects and interprets this backscatter and sends the data to a microcontroller(NodeMcu in our case).

2] Once the Microcontroller receives the data, it process the data, the data is a string of 16 characters which is identity of user. Now the microcontroller processes the data by adding data and time along with the card data.
3] Microcontroller sends a get request to google sheet url. 
4] The request send by microcontroller is handled by javaScript function which adds the parameters(name, date and time) into google sheet.

### Refer circuit diagram from the 'GUIDE.pdf'
