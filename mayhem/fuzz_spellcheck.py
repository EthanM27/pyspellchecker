#! /usr/bin/python3

import atheris
import sys

with atheris.instrument_imports():
    from spellchecker import SpellChecker

spell = SpellChecker()

@atheris.instrument_func
def test_input(data):    
    fdp = atheris.FuzzedDataProvider(data)
    s = fdp.ConsumeString(4096)

    spell.correction(s)
    spell.candidates(s)

def main():
    atheris.Setup(sys.argv, test_input)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
