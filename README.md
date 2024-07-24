# wsbase

-----

Websocket client server base package.

**Table of Contents**

- [Installation](#installation)
- [Features](#features)
- [Development Environment](#development-environment)
- [Testing](#testing)
- [License](#license)

## Installation

```shell
$ pip install git+https://github.com/DamianPala/wsbase.git
```

## Features

 - Minimal final Client and Server implementation.
 - Asynchronous BaseServer implementation.
 - Supports SSL by default with automatic self-signed certificate generation.
 - Uses pydantic to serialize and deserialize python objects.
 - Serializes and recreates exceptions.
 - Server has operates in separate thread so instance is nonblocking.

## Development Environment

1. Install min Python 3.11
2. Install `hatchling` globally:

   ```shell
   $ python -m pip install hatch
   ```
   
   or

   ```shell
   $ pipx install hatch
   ```

3. Open root package directory, create a virtual environment, install dependencies and enter the shell (OPTIONAL).  

   ```shell
   $ hatch shell
   ```

## Testing

For testing, `hatchling` will create virtual environment automatically.  
To run a test you can use the command like this:

```shell
$ hatch test -- -s tests/test_filename.py::TestClass::test_name
```

or

```shell
$ hatch test
```

To run all tests.

> **WARNING!** There is a bug in hatchling 1.12.0 affecting testing. In case of test is not finding sources execute one time:
> `hatch test -py X.X` where `X.X` is your python version. 

## License

`logger` is distributed under the terms of the [MIT](https://spdx.org/licenses/MIT.html) license.
