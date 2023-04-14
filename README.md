# My first Industrial Edge App - App Developer Guide

Creating a first Industrial Edge App on a development environment to deploy it to an Industrial Edge Device based on App Developer Guide.

- [My first Industrial Edge App - App Developer Guide](#my-first-industrial-edge-app---app-developer-guide)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Description](#description)
  - [Documentation](#documentation)
  - [Contribution](#contribution)
  - [License and Legal Information](#license-and-legal-information)
  - [Disclaimer](#disclaimer)

## Prerequisites

Prerequisites are in the App Developer Guide which is available on [industrial-edge.io](https://docs.eu1.edge.siemens.cloud/develop_an_application/developer_guide/00_Overview.html). It contains description of the requirements as well as the step-by-step description how to work with this Developer Guide repository.

## Installation

If you would like to run the solution of this app you need to rename all files called "Dockerfile.example" to Dockerfile. These Dockerfiles are just an example how you could implement it.

## Description

As the example app will cover the most common use case in the Industrial Edge environment, the app on the Industrial Edge Device will look like the architectural overview in the figure below. The goal of the app will be to collect, process and store data from an OPC UA Server, which provides data from a PLC.

![Overview of app architecture](./docs/Picture_5_3_Architecture_IED.png)

The app contains three parts – the connectivity to collect the data from the OPC UA Server by system apps, the IE Databus for distributions of the data and the process, storing and visualization of data in the Edge App.

1. The **IE Databus** based on MQTT is responsible for distributing data to certain topics, that are filled by system or custom apps by publishing and subscribing to these topics.
2. To receive the data from the OPC UA server, which is providing data from a PLC, the **OPC UA Connector connectivity** is used. OPC UA Connector is a system app, that publishes the data to IE Databus. Another system app, the SIMATIC Flow Creator, consumes the data from the OPC UA Connector topics on the IE Databus. The data is preprocessed in the SIMATIC Flow Creator before being published on the IE Databus again.
3. The developed **data analytics container** with Python is consuming the preprocessed data on the topics from the SIMATIC Flow Creator. The Python data analytics performs calculations and evaluations and returns the results as KPIs back to the IE Databus. To handle the IE Databus publishes and subscriptions, the data analytics container requires a MQTT client.
4. The **SIMATIC Flow Creator** consumes the analyzed data again. The SIMATIC Flow Creator persistently stores the (raw) and analyzed data in InfluxDB.
5. The **InfluxDB** is a time series database which is optimized for fast, high-availability storage and retrieval of time series data. It stores both the data transmitted by the OPC UA server to the app and the analyzed data.
6. The data stored in the database can be queried and graphed in dashboards to format them and present them in meaningful and easy to understand way. There are many types of dashboards to choose from including those that come with InfluxDB or other open source projects like Grafana. In this application, the native **InfluxDB Dashboards** are leveraged for basic data visualization.

## Documentation

- Here is a link to the [industrial-edge.io](https://docs.eu1.edge.siemens.cloud/develop_an_application/developer_guide/00_Overview.html) where the App Developer Guide of this application example can be found.
- You can find further documentation and help in the following links
  - [Industrial Edge Hub](https://iehub.eu1.edge.siemens.cloud/#/documentation)
  - [Industrial Edge Forum](https://www.siemens.com/industrial-edge-forum)
  - [Industrial Edge landing page](http://siemens.com/industrial-edge)
  
## Contribution

Thank you for your interest in contributing. Anybody is free to report bugs, unclear documentation, and other problems regarding this repository in the Issues section.
Additionally everybody is free to propose any changes to this repository using Pull Requests.

If you are interested in contributing via Pull Request, please check the [Contribution License Agreement](Siemens_CLA_1.1.pdf) and forward a signed copy to [industrialedge.industry@siemens.com](mailto:industrialedge.industry@siemens.com?subject=CLA%20Agreement%20Industrial-Edge).

## License and Legal Information

Please read the [Legal information](LICENSE.txt).

## Disclaimer

IMPORTANT - PLEASE READ CAREFULLY:

This documentation describes how you can download and set up containers which consist of or contain third-party software. By following this documentation you agree that using such third-party software is done at your own discretion and risk. No advice or information, whether oral or written, obtained by you from us or from this documentation shall create any warranty for the third-party software. Additionally, by following these descriptions or using the contents of this documentation, you agree that you are responsible for complying with all third party licenses applicable to such third-party software. All product names, logos, and brands are property of their respective owners. All third-party company, product and service names used in this documentation are for identification purposes only. Use of these names, logos, and brands does not imply endorsement.
