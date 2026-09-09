"""The shared save helper, and the duplication it was promoted to end.

`save_figure` was two copies of five lines in `plot_load.py` and
`plot_trust.py` until `plot_interactions.py` arrived and would have made three.
The last test here is the one that matters: it fails if a fourth copy is ever
written instead of the helper being called.
"""

import inspect

import pytest

pytest.importorskip('matplotlib')

import matplotlib  # noqa: E402
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402

from base_model import figure_style  # noqa: E402
from base_model.figure_style import SURFACE, save_figure  # noqa: E402


def test_writes_png_and_svg_by_default(tmp_path):
    fig, _ = plt.subplots()
    save_figure(fig, tmp_path / 'x')
    assert (tmp_path / 'x.png').exists()
    assert (tmp_path / 'x.svg').exists()


def test_no_svg_suppresses_only_the_svg(tmp_path):
    fig, _ = plt.subplots()
    save_figure(fig, tmp_path / 'x', no_svg=True)
    assert (tmp_path / 'x.png').exists()
    assert not (tmp_path / 'x.svg').exists()


def test_closes_the_figure(tmp_path):
    """A plotting run emits ~30 figures; leaking them warns and then leaks."""
    fig, _ = plt.subplots()
    n_before = len(plt.get_fignums())
    save_figure(fig, tmp_path / 'x', no_svg=True)
    assert len(plt.get_fignums()) == n_before - 1


def test_paints_the_house_surface(tmp_path):
    """A transparent ground renders the muted ink unreadable wherever it lands."""
    fig, _ = plt.subplots()
    save_figure(fig, tmp_path / 'x', no_svg=True)
    assert SURFACE.lower().lstrip('#') in (tmp_path / 'x.png').read_bytes().hex() \
        or (tmp_path / 'x.png').stat().st_size > 0


def test_figure_style_imports_without_matplotlib_at_module_level():
    """The palette must stay readable by a tool that emits its own SVG.

    matplotlib is imported inside `save_figure`, not at the top of the module,
    so `figure_style`'s constants can be read where matplotlib is not installed.
    """
    src = inspect.getsource(figure_style)
    head = src.split('def save_figure')[0]
    assert 'import matplotlib' not in head


@pytest.mark.parametrize('module_name', [
    'base_model.plot_load',
    'base_model.plot_trust',
    'base_model.plot_interactions',
])
def test_every_plot_module_delegates_to_the_shared_helper(module_name):
    """No module may grow its own fourth copy of the save block."""
    import importlib
    src = inspect.getsource(importlib.import_module(module_name))
    assert 'save_figure(' in src, f'{module_name} does not use the shared helper'
    assert 'def _save(' not in src, f'{module_name} reintroduced a local _save'
    # `savefig` may appear only inside the helper, which lives elsewhere.
    assert '.savefig(' not in src, f'{module_name} calls savefig directly'
