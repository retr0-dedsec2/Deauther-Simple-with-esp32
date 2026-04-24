# Deauther-Simple-with-esp32

You want a good project ethical hacking with wifi deauth this repo is for you

## How to build PlatformIO based project

1. [Install PlatformIO Core](https://docs.platformio.org/page/core.html)
2. Download [This repo github](https://github.com/retr0-dedsec2/Deauther-Simple-with-esp32)
3. Extract ZIP archive
4. Run these commands:

```shell
# Change directory to example
$ cd Deauther-Simple-with-esp32
or (if its fail)
$ cd Deauther-Simple-with-esp32-main

# Build project
$ pio run

# Upload firmware
$ pio run --target upload

# Build specific environment
$ pio run -e esp32dev

# Upload firmware for the specific environment
$ pio run -e esp32dev --target upload

# Clean build files
$ pio run --target clean
```
