# ws-base

-----

**Table of Contents**

- [Installation](#installation)
- [License](#license)

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

3. Open root package directory, create a virtual environment and install dependencies (OPTIONAL).  

   ```shell
   $ hatch env create
   ```

## Testing

For testing, `hatchling` will create virtual environment automatically.  
To run a test you can use command like this:

```shell
$ hatch test -- -s tests/dex_test.py::test_make_trade_output[ethereum-uniswap_v2]
```

> **WARNING!** There is a bug in hatchling affecting testing. In case of test is not finding sources execute one time:
> `hatch test -py 3.11`

## License

`ws-base` is distributed under the terms of the [MIT](https://spdx.org/licenses/MIT.html) license.
