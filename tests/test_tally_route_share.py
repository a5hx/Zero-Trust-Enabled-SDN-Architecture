"""Tests for evaluation/tally_route_share.py -- the live-run route-share tally
that turns a controller event recording into per-node counts (SETUP §3b-routing,
Figure 11 of the study)."""

from evaluation.tally_route_share import tally


def test_counts_only_route_events_by_chosen_node(tmp_path):
    log = tmp_path / 'events.jsonl'
    log.write_text('\n'.join([
        '{"type":"route","chosen":"srv1"}',
        '{"type":"route","chosen":"srv4"}',
        '{"type":"report","node":"srv1"}',      # not a route event
        '{"type":"route","chosen":"srv1"}',
        '{"type":"route"}',                       # route with no chosen -> ignored
    ]) + '\n')
    assert tally(str(log)) == {'srv1': 2, 'srv4': 1}


def test_tolerates_blank_and_truncated_lines(tmp_path):
    log = tmp_path / 'events.jsonl'
    log.write_text(
        '{"type":"route","chosen":"srv2"}\n'
        '\n'
        '{"type":"route","chosen":"srv2"}\n'
        '{"type":"route","chosen":"srv3'          # truncated final line, no newline
    )
    assert tally(str(log)) == {'srv2': 2}


def test_empty_log_yields_no_counts(tmp_path):
    log = tmp_path / 'events.jsonl'
    log.write_text('')
    assert tally(str(log)) == {}
