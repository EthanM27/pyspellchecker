#!/usr/local/bin/python3
import atheris
import sys

from spellchecker import SpellChecker

spell = SpellChecker()


@atheris.instrument_func
def TestOneInput(data):
    try:
        txt = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    
    res = spell.unknown(txt.split(" "))
    for word in res:
        spell.correction(word)
        spell.candidates(word)
    spell.known(txt.split(" "))


atheris.instrument_all()
atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()