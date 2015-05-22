#!/bin/sh
i18ndude rebuild-pot --pot "locales/AutoUserMakerPASPlugin.pot" --create AutoUserMakerPASPlugin .
i18ndude sync --pot "locales/AutoUserMakerPASPlugin.pot" \
    "locales/de/LC_MESSAGES/AutoUserMakerPASPlugin.po" \
    "locales/en/LC_MESSAGES/AutoUserMakerPASPlugin.po" \
    "locales/fr/LC_MESSAGES/AutoUserMakerPASPlugin.po"
