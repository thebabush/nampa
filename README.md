# Nampa - FLIRT for (binary) ninjas

*Pure-python implementation of IDA Pro's FLIRT technology. Also Binary Ninja plugin.*

## Description

Nampa is a package for reading IDA Pro's `.sig` files.
It comes with its own command-line tool for analyzing such files: `dumpsig.py`.

Nampa the package is completely decoupled from the Binary Ninja plugin.

Nampa the plugin comes with a small library of `.sig` files, automatically
downloaded from 3rd-party GitHub repositories when needed.

## Screenshot

![Dialog](./img/dialog.png)

## Installation

For use as a python library:

```bash
pip install nampa
```

For use as a Binary Ninja plugin:

```bash
cd ~/.binaryninja/plugins/
git clone git@github.com:thebabush/nampa.git
cd nampa
pip install -r requirements.txt # or sudo apt-get install python-future
```

**NOTE:** apparently, Binary Ninja for Windows ships with its own python distribution so `pip install` accordingly.

## About

[Meaning of Nampa (ナンパ)](http://jisho.org/search/%E8%BB%9F%E6%B4%BE).

### Limitations

Ref functions are not implemented at the moment.

### Thanks

- `radare` people, since this is basically a python port of
[radare's FLIRT implementation](https://raw.githubusercontent.com/radare/radare2/e8f80a165c7dd89d955a1ee7f432bd9a1ba88976/libr/anal/flirt.c).
- [trib0r3](https://github.com/trib0r3) for updating the Binary Ninja integration

### License

The original radare's flirt.c is under LGPL, so my deep knowledge of software licenses tells me that I must keep it
that way.
