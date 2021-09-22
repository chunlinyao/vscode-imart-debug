# VS Code Intramart Debug

This is a intramart VS Code debug adapters.

**Imart Debug** attach to remote intramart instance, and debugging jssp script.

## Using Imart Debug

* Install the **Imart Debug** extension in VS Code.
* Config jvm args to resin.

      -Djp.co.intra_mart.system.javascript.Debugger.port=9000
* Create `launch.json`
  
      {
        "version": "0.2.0",
        "configurations": [
          {
            "type": "imart",
            "request": "attach",
            "name": "Debug Imart",
            "trace": true,
            "localRoot": "${workspaceFolder}/src/main/jssp",
            "port": 9000,
          }
        ]
      }
* `F5` to start it.

