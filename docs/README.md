---
home: true
heroImage: /images/logo.png
heroText: YSF Reflector in Go
tagline: A Modern Approach to Building a YSF Reflector in Golang
# actionText: Get Started →
# actionLink: /guide/
features:
  - title: Golang-Powered
    details: Built using Go for efficiency, scalability, and performance.
  - title: Modern Design
    details: Incorporating best practices for modern software development.
  - title: Easy to Integrate
    details: Aiming for seamless integration with existing YSF ecosystems.
footer: MIT Licensed | Created by [Roger M. Nabinger]
---

## Project Overview

This project aims to develop a **YSF Reflector** using the **Go programming language** (Golang). YSF Reflectors are critical components in digital voice communication, especially in the **Yaesu System Fusion (YSF)** network, where they enable linking and routing between various nodes and repeaters.

Our goal is to leverage the performance and concurrency capabilities of Go to build a fast, reliable, and easy-to-deploy YSF Reflector that improves upon existing solutions in terms of speed, maintainability, and extensibility.

## Features and Objectives

- **Written in Go**: Utilizing Go's simplicity and high performance to create a lightweight and fast reflector.
- **Efficient Packet Handling**: Handling YSF packets effectively to maintain high-speed communication.
- **Customizable and Extendable**: Modular design allowing for easy enhancements and custom features.
- **Integration with Existing Systems**: Compatible with popular systems like Pi-Star for seamless use in real-world setups.

## Why Go?

- **Concurrency**: Go’s built-in concurrency model allows for handling multiple connections efficiently.
- **Performance**: Go offers near-C performance, which is critical for high-traffic systems.
- **Simplicity**: Go's simplicity allows for writing clear and maintainable code, perfect for network-based applications.

## Current Status

The project is currently in active development, with a focus on:

- UDP packet handling and parsing for YSF communication.
- Basic command structure for login (YSFP) and logout (YSFU) requests.
- Response handling for incoming connections and status requests.
  
Stay tuned as we continue to develop new features and improve the reflector's functionality.

## Get Involved

Feel free to contribute to this project! Check out the [GitHub repository](https://github.com/elteser/goYSFReflector) for more details on how to get involved.
