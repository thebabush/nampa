#!/bin/sh

f=requirements.txt
pip freeze > $f
sed -i '/^appdirs==/d' $f
sed -i '/^packaging==/d' $f
sed -i '/^pkg-resources==/d' $f
sed -i '/^pyparsing==/d' $f
sed -i '/^six==/d' $f
