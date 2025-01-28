# StratumSimulator
This project offers a convenient way to test SHA256-based cryptocurrency miners. 
It enables developers or users to connect to a simulated Stratum server and mine 
virtual blocks at a customizable difficulty level. It is meant to be compiled
through the Arduino IDE and deployed on ESP32 devices.


## Compiling

Ensure that you have installed the ESP32 and [ArduinoJson](https://arduinojson.org/) libaries.
Compile using the Arduino IDE.
Modify the defines, if needed, to suit your needs.
WiFi information can be hard-coded in the defines or set through the serial console.

## Usage

Get the simulator's IP address from the serial console.

Set your miner to point to the IP address and port of your simulator.

The serial log will show ongoing statistics and other information.
