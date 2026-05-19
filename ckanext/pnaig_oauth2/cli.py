# -*- coding: utf-8 -*-

import click


@click.group()
def pnaig_oauth2():
    """PNAIG OAuth2 management commands.
    """
    pass


def get_commands():
    return [pnaig_oauth2]
