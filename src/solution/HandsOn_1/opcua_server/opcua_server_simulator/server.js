"use strict";
const path = require("path");
const _ = require("underscore");
const assert = require("assert");
const opcua = require("node-opcua");
var config = require(process.cwd() + "/config");
Error.stackTraceLimit = Infinity;
//to pass path of server certificate and key
function constructFilename(filename) {
    return path.join(__dirname, "../", filename);
}

const yargs = require("yargs/yargs");
const argv = yargs(process.argv);

const OPCUAServer = opcua.OPCUAServer;
const Variant = opcua.Variant;
const DataType = opcua.DataType;
const get_fully_qualified_domain_name = opcua.get_fully_qualified_domain_name;
const port = config.datasource.dataaquisition.port;



//to get server meta data
const server_options = {
    port: port,
//server parameter
    serverInfo: {
        productUri: "NodeOPCUA-Server",
        applicationName: { text: "NodeOPCUA", locale: "en" },
        gatewayServerUri: null,
        discoveryProfileUri: null,
        discoveryUrls: []
    },
    isAuditing: false,
};

process.title = "Node OPCUA Server on port : " + server_options.port;

server_options.alternateHostname = config.datasource.dataaquisition.host;

const server = new OPCUAServer(server_options);

const hostname = require("os").hostname();
//define variables to hold simulated data
var voltage1, voltage2, voltage3, power1, power2, power3, current1, current2, current3, temp1, temp2 = 0.0;
var uptime = 0;

/**
 * defineDataHierachy
 * This function is responsible for creating data hierachy and defining variables
 * @param {*} 
 */
function defineDataHierachy() {
    const addressSpace = server.engine.addressSpace;
    const rootFolder = addressSpace.findNode("RootFolder");
    assert(rootFolder.browseName.toString() === "Root");
    //create 4 folders for simulating 4 machines 
    const namespace = addressSpace.getOwnNamespace()
    const drehmaschine = namespace.addFolder(rootFolder.objects, { browseName: "Rotating Machine1" });
    const drehmaschine2 = namespace.addFolder(rootFolder.objects, { browseName: "Rotating Machine2" });
    const fraesmaschine = namespace.addFolder(rootFolder.objects, { browseName: "Milling Machine1" });
    const fraesmaschine2 = namespace.addFolder(rootFolder.objects, { browseName: "Milling Machine2" });

    //Adding variables to data folders
    //register voltages
    voltage1 = namespace.addVariable({
        organizedBy: drehmaschine,
        browseName: "Voltage_Drive_1",
        nodeId: "ns=1;s=voltagedrive1",
        dataType: "Double",
        value: new Variant({ dataType: DataType.Double, value: 0 })
    });
    voltage2 = namespace.addVariable({
        organizedBy: drehmaschine,
        browseName: "Voltage_Drive_2",
        nodeId: "ns=1;s=voltagedrive2",
        dataType: "Double",
        value: new Variant({ dataType: DataType.Double, value: 0 })
    });
    voltage3 = namespace.addVariable({
        organizedBy: drehmaschine,
        browseName: "Voltage_Drive_3",
        nodeId: "ns=1;s=voltagedrive3",
        dataType: "Double",
        value: new Variant({ dataType: DataType.Double, value: 0 })
    });
    //register power
    power1 = namespace.addVariable({
        organizedBy: drehmaschine2,
        browseName: "Power_Drive_1",
        nodeId: "ns=1;s=powerdrive1",
        dataType: "Double",
        value: new Variant({ dataType: DataType.Double, value: 0 })
    });
    power2 = namespace.addVariable({
        organizedBy: drehmaschine2,
        browseName: "Power_Drive_2",
        nodeId: "ns=1;s=powerdrive2",
        dataType: "Double",
        value: new Variant({ dataType: DataType.Double, value: 0 })
    });
    power3 = namespace.addVariable({
        organizedBy: drehmaschine2,
        browseName: "Power_Drive_3",
        nodeId: "ns=1;s=powerdrive3",
        dataType: "Double",
        value: new Variant({ dataType: DataType.Double, value: 0 })
    });
    //register current
    current1 = namespace.addVariable({
        organizedBy: fraesmaschine,
        browseName: "Current_Drive_1",
        nodeId: "ns=1;s=currentdrive1",
        dataType: "Double",
        value: new Variant({ dataType: DataType.Double, value: 0 })
    });
    current2 = namespace.addVariable({
        organizedBy: fraesmaschine,
        browseName: "Current_Drive_2",
        nodeId: "ns=1;s=currentdrive2",
        dataType: "Double",
        value: new Variant({ dataType: DataType.Double, value: 0 })
    });
    current3 = namespace.addVariable({
        organizedBy: fraesmaschine,
        browseName: "Current_Drive_3",
        nodeId: "ns=1;s=currentdrive3",
        dataType: "Double",
        value: new Variant({ dataType: DataType.Double, value: 0 })
    });
    //register temperature
    temp1 = namespace.addVariable({
        organizedBy: fraesmaschine2,
        browseName: "Temperatur1",
        nodeId: "ns=1;s=temperatur1",
        dataType: "Double",
        value: new Variant({ dataType: DataType.Double, value: 0 })
    });
    temp2 = namespace.addVariable({
        organizedBy: fraesmaschine2,
        browseName: "Temperatur2",
        nodeId: "ns=1;s=temperatur2",
        dataType: "Double",
        value: new Variant({ dataType: DataType.Double, value: 0 })
    });
    uptime = namespace.addVariable({
        organizedBy: fraesmaschine2,
        browseName: "upTime",
        nodeId: "ns=1;s=uptime",
        dataType: "Double",
        value: new Variant({ dataType: DataType.Double, value: uptime
         })
        
    });

}
//this asynchrounous function is writing simulating values to the wanted OPC datapoint
server.on("post_initialize", function () {

    opcua.build_address_space_for_conformance_testing(server.engine.addressSpace);
    //call the routine to define data points
    defineDataHierachy();
    //generate value for this variable between 236 and 241 Volt
    //in an interval of 30 milliseconds 
    setInterval(function () {
        voltage1.setValueFromSource(new Variant({ dataType: DataType.Double, value: (Math.random() * (241.0 - 236.0 + 1) + 241.0)}));
        voltage3.setValueFromSource(new Variant({ dataType: DataType.Double, value: (Math.random() * (241.0 - 236.0 + 1) + 241.0)}));
        current1.setValueFromSource(new Variant({ dataType: DataType.Double, value: (Math.random() * (10.0 - 3.0 + 1) + 10.0)}));
    }, 30);//milliseconds

    //generate value for this variable
    //Math.random() * (max - min) + min;
    //in an interval of 50 milliseconds 
    setInterval(function () {
        voltage2.setValueFromSource(new Variant({ dataType: DataType.Double, value: (Math.random() * (241.0 - 236.0 + 1) + 236.0 )}));
        //values between 800 and 999 Watt 
        power3.setValueFromSource(new Variant({ dataType: DataType.Double, value: (Math.random() * (999.0 - 800.0 + 1) + 800.0)}));
        current2.setValueFromSource(new Variant({ dataType: DataType.Double, value: (Math.random() * (10.0 - 3.0 + 1) + 3.0 )}));
    }, 50);//milliseconds

    //generate value for this variable between 236 and 241
    //in an interval of 30 milliseconds 
    setInterval(function () {
        //values between 750 and 999 Watt
        power1.setValueFromSource(new Variant({ dataType: DataType.Double, value: (Math.random() * (999.0 - 750.0 + 1) + 750.0)}));
        //values between 800 and 999 Watt 
        power2.setValueFromSource(new Variant({ dataType: DataType.Double, value: (Math.random() * (999.0 - 800.0 + 1) + 800.0)}));
        current3.setValueFromSource(new Variant({ dataType: DataType.Double, value: (Math.random() * (10.0 - 3.0 + 1) + 3.0)}));
    }, 80);//milliseconds

    //generate value for this variable between 236 and 241
    //in an interval of 130 milliseconds 
    setInterval(function () {
        //call the increase routine
        var ctr = increaseUptime();
        //values between 750 and 999 Watt
        temp1.setValueFromSource(new Variant({ dataType: DataType.Double, value: (Math.random() * (110.0 - 70.0 + 1) + 70.0)}));
        //values between 800 and 999 Watt 
        temp2.setValueFromSource(new Variant({ dataType: DataType.Double, value: (Math.random() * (110.0 - 70.0 + 1) + 70.0)}));
        //set ctr as uptime
        uptime.setValueFromSource(new Variant({ dataType: DataType.Double, value: ctr}));
    }, 130);//milliseconds

});
//declare variable to simulate a machine uptime
var counter = 0;
//this function should simulate a machine uptime
function increaseUptime ()
{
    //keep increasing while the counter is smaller 60000
    if (counter < 60000){
        ++counter;
    }
    //after 60000 do a reset
    else {
        counter = 0;
    }
    return counter;
}

console.log("  server PID          :", process.pid);
//asynchrounous function called after server start
server.start(function (err) {
    if (err) {
        console.log(" Server failed to start ... exiting");
        process.exit(-3);
    }
    console.log("  server on port      :", server.endpoints[0].port.toString());
    console.log("\n  server now waiting for connections. CTRL+C to stop");

});
//asynchorunous function which gets called after the session with a client is established
server.on("create_session", function (session) {
    console.log(" SESSION CREATED");
    console.log("        client product URI: ", session.clientDescription.productUri);
});
//asynchorunous function which gets called after the session with a client gets closed
server.on("session_closed", function (session, reason) {
    console.log(" SESSION CLOSED :", reason);
    console.log("              session name: ", session.sessionName ? session.sessionName.toString() : "<null>");
});

//to be able to end process on server terminal
process.on("SIGINT", function () {
    // only work on linux apparently
    console.error(" Received server interruption from user ");
    console.error(" shutting down ...");
    server.shutdown(1000, function () {
        console.error(" shutting down completed ");
        console.error(" done ");
        process.exit(-1);
    });
});

server.on("serverRegistered", function () {
    console.log("server has been registered");
});
server.on("serverUnregistered", function () {
    console.log("server has been unregistered");
});
//asynchorunous function which gets called after the session with a client gets connected to our server
server.on("newChannel", function (channel) {
    console.log("Client connected with address = ", channel.remoteAddress, " port = ", channel.remotePort);
});
//asynchorunous function which gets called after the session with a client gets closed
server.on("closeChannel", function (channel) {
    console.log("Client disconnected with address = ", channel.remoteAddress, " port = ", channel.remotePort);
    if (global.gc) {
        global.gc();
    }
});