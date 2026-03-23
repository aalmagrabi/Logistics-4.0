# Logistics 4.0 Three-Party Mutual Authentication Protocol

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

This repository contains the complete testbed implementation of the **Three-Party Mutual Authentication Scheme for Logistics 4.0**, as presented in the manuscript. The protocol enables secure authentication among three entities: **User (Operator Device)**, **Cloud Server**, and **E-Tag** in a single session—a critical requirement for real-world logistics operations.

## Key Contributions

- ✅ **First three-party mutual authentication protocol** purpose-built for Logistics 4.0
- ✅ **Record-low computation time**: 16.87 ms (6.63× faster than existing schemes)
- ✅ **Low communication overhead**: 2688 bits (63.7% reduction)
- ✅ **Dynamic key management** for secure device decommissioning
- ✅ **Multi-layered formal verification**: BAN logic, ProVerif, RoR model

## Features

- **Registration Phase**: Secure offline registration for E-Tags and Operator Devices
- **Authentication Phase**: Three-party mutual authentication with session key agreement
- **Key Update Phase**: Dynamic key refresh and revocation without re-registration
- **Performance Metrics**: Computation time, communication overhead, energy consumption
- **Visualization**: Automated plotting of performance comparisons

## Requirements

- Python 3.8 or higher
- Dependencies listed in `requirements.txt`

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/logistics40-authentication.git
cd logistics40-authentication

# Install dependencies
pip install -r requirements.txt
