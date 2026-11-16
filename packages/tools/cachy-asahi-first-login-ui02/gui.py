# SPDX-License-Identifier: MIT
"""Original opt-in first-login GTK4 application."""
import argparse
import importlib.util
from pathlib import Path
import sys
import threading


def sibling(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


bridge = sibling('bridge')


def action_text(row):
    labels = {'fish': 'Fish', 'zsh': 'Zsh', 'hyprland': 'Hyprland'}
    actions = {'would-add': 'Add settings', 'would-update': 'Update managed settings',
        'would-remove': 'Remove the original managed settings', 'add': 'Settings added',
        'would-splice': 'Resume updating the managed settings block',
        'would-file': 'Resume restoring the configuration copy',
        'update': 'Managed settings updated', 'remove': 'Managed settings removed',
        'unchanged': 'Already configured', 'already-applied': 'Already completed',
        'already-absent': 'Already absent', 'unmanaged': 'No managed settings yet',
        'clean': 'Managed settings are unchanged', 'drifted': 'Your edits need review',
        'missing': 'Managed settings are missing', 'conflicting': 'Existing settings need review',
        'unknown': 'Could not inspect safely', 'preserved-edited': 'Your edits are preserved; changes blocked',
        'preserved-existing': 'Existing configuration is preserved; changes blocked'}
    if row['status'] in ('would-remove', 'remove'):
        actions[row['status']] = (('Delete unchanged managed configuration copy' if row['status'] == 'would-remove' else 'Managed configuration copy removed')
            if row['component'] == 'hyprland' else ('Remove managed shell settings block' if row['status'] == 'would-remove' else 'Managed shell settings block removed'))
    return (labels.get(row['component'], row['component']) + ': '
            + actions.get(row['status'], 'Review this configuration action')
            + (' — ' + row['path'] if row.get('path') else ''))


def window_class():
    import gi
    gi.require_version('Gtk', '4.0')
    from gi.repository import Gtk, GLib

    class Window(Gtk.ApplicationWindow):
        def __init__(self, app, client):
            super().__init__(application=app, title='Set up your Cachy-Asahi settings', default_width=680, default_height=720)
            self.client, self.busy, self.closing = client, False, False
            self.available, self.managed = {}, {}
            self.ready = self.recovery = False
            self.worker = None
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12,
                          margin_top=20, margin_bottom=20, margin_start=20, margin_end=20)
            self.set_child(box)
            title = Gtk.Label(label='Manage your Cachy-Asahi settings', xalign=0)
            title.add_css_class('title-1'); box.append(title)
            box.append(Gtk.Label(label='Choose settings to add or remove. Preview each change, then confirm.\nYour existing edits are preserved. Nothing starts automatically.',
                                 xalign=0, wrap=True))
            self.choices = {}
            for name, label in (('fish', 'Fish shell settings'), ('zsh', 'Zsh shell settings'),
                                ('hyprland', 'Hyprland configuration copy')):
                button = Gtk.CheckButton(label=label)
                button.connect('toggled', self.selection_changed)
                box.append(button); self.choices[name] = button
            box.append(Gtk.Label(label='Shell settings take effect in a fresh shell. Hyprland activation\ndoes not launch or select a graphical session.', xalign=0, wrap=True))
            row = Gtk.Box(spacing=8); box.append(row)
            self.refresh = Gtk.Button(label='Inspect again')
            self.preview = Gtk.Button(label='Preview settings')
            self.apply = Gtk.Button(label='Apply settings')
            self.apply.add_css_class('suggested-action')
            for button, action in ((self.refresh, 'inspect'), (self.preview, 'preview'), (self.apply, 'apply')):
                row.append(button); button.connect('clicked', lambda _, action=action: self.start(action))
            removal_row = Gtk.Box(spacing=8); box.append(removal_row)
            self.remove_preview = Gtk.Button(label='Preview removal')
            self.remove_apply = Gtk.Button(label='Remove reviewed settings')
            self.remove_apply.add_css_class('destructive-action')
            self.remove_preview.connect('clicked', lambda _: self.start('remove-preview'))
            self.remove_apply.connect('clicked', lambda _: self.start('apply'))
            removal_row.append(self.remove_preview); removal_row.append(self.remove_apply)
            box.append(Gtk.Label(label='Removal deletes only managed settings; your other edits stay.\nSwitch Hyprland to your previous configuration before removing its copy.', xalign=0, wrap=True))
            recovery_row = Gtk.Box(spacing=8); box.append(recovery_row)
            self.recovery_row = recovery_row; recovery_row.set_visible(False)
            self.recover_preview = Gtk.Button(label='Preview pending recovery')
            self.recover_apply = Gtk.Button(label='Resume pending recovery')
            self.recover_preview.connect('clicked', lambda _: self.start('recover-preview'))
            self.recover_apply.connect('clicked', lambda _: self.start('apply'))
            recovery_row.append(self.recover_preview); recovery_row.append(self.recover_apply)
            self.status = Gtk.Label(label='Inspecting available settings…', xalign=0, wrap=True, selectable=True)
            box.append(self.status)
            self.details = Gtk.Label(xalign=0, yalign=0, wrap=True, selectable=True)
            scroll = Gtk.ScrolledWindow(vexpand=True, min_content_height=130)
            scroll.set_child(self.details); box.append(scroll)
            self.connect('close-request', self.close_requested)
            self.start('inspect')

        def selected(self):
            return tuple(name for name, button in self.choices.items() if button.get_active())

        def selection_changed(self, *_):
            self.client.invalidate(); self.update_buttons()

        def update_buttons(self):
            for name, button in self.choices.items():
                button.set_sensitive(not self.busy and self.ready and (self.available.get(name, False) or self.managed.get(name, False)))
            self.refresh.set_sensitive(not self.busy)
            self.preview.set_sensitive(not self.busy and self.ready and bool(self.selected())
                                       and all(self.available.get(c, False) for c in self.selected()))
            self.remove_preview.set_sensitive(not self.busy and self.ready and bool(self.selected()))
            self.recover_preview.set_sensitive(not self.busy and self.recovery)
            ticket = self.client.ticket
            self.apply.set_sensitive(not self.busy and ticket is not None and ticket[0] == 'activate')
            self.recover_apply.set_sensitive(not self.busy and ticket is not None and ticket[0] == 'recover')
            self.remove_apply.set_sensitive(not self.busy and ticket is not None and ticket[0] == 'remove')

        def start(self, action):
            if self.busy:
                return
            self.busy = True
            self.client.cancel.clear()
            components = self.selected()
            self.status.set_text('Checking your settings…' if action != 'apply' else 'Applying the reviewed changes…')
            self.update_buttons()
            def work():
                try:
                    result, error = self.client.run(action, components if action in ('preview', 'remove-preview') else ()), None
                except Exception as failure:
                    result, error = None, str(failure) if isinstance(failure, bridge.Error) else 'The action could not complete. Preserve your edits and inspect again.'
                GLib.idle_add(self.finished, result, error)
            self.worker = threading.Thread(target=work, name='first-login-action')
            self.worker.start()

        def finished(self, result, error):
            self.worker.join(); self.worker = None
            self.busy = False
            if self.closing:
                self.destroy(); return False
            if error:
                self.status.set_text(error); self.ready = self.recovery = False
                self.client.invalidate(); self.details.set_text('No further action is enabled. Inspect again before retrying.')
            else:
                report, code = result
                pending = report['setup_status'].get('pending', {}).get('status')
                self.recovery_row.set_visible(pending != 'none')
                self.ready = pending == 'none' and code != 1
                self.recovery = pending == 'resumable' and code != 1
                if report.get('status') in ('recovery-applied', 'removal-attention'):
                    self.ready = self.recovery = False
                self.managed = {r['component']: r.get('ownership') == 'managed'
                    for r in report['setup_status'].get('actions', [])}
                for component in report['components']:
                    self.available[component['component']] = component['available']
                messages = {'ready-to-select': 'Choose the settings you want to preview.',
                    'attention-required': 'Some settings need attention. Inspect the details before continuing.',
                    'activation-preview': 'Preview ready. Review the actions below, then apply your selected settings.',
                    'activation-applied': 'Settings applied. Open a fresh shell to use your shell settings.',
                    'removal-preview': 'Removal preview ready. Review exactly which managed settings change, then confirm removal.',
                    'removal-applied': 'Managed settings removed. Open fresh shells; already-running sessions keep their settings.',
                    'removal-attention': 'Removal needs attention. Review each result; preserved edits and any concurrent recovery remain visible.',
                    'blocked': 'Changes are blocked. Preserve your edits and review the details.',
                    'recovery-required': 'An interrupted configuration change needs attention.',
                    'recovery-preview': 'Recovery preview ready. Resuming restores the original transaction.',
                    'recovery-applied': 'Pending recovery completed. Inspect again before choosing new settings.'}
                self.status.set_text(messages.get(report.get('status'), 'Review the reported settings before continuing.'))
                if report.get('status') == 'removal-preview' and self.client.ticket is None:
                    self.status.set_text('None of these selected settings need removal. Your existing files stay unchanged.')
                rows = report.get('setup_result', report['setup_status']).get('actions', [])
                lines = [action_text(row) for row in rows[:30]]
                if report.get('operation') == 'remove':
                    lines += ['Empty files originally created by setup may also be deleted.',
                              'Unselected managed modules and other user settings stay in place.']
                for component in report['components']:
                    if not component['available'] and report.get('operation') != 'remove':
                        lines.append(component['component'] + ': install its program and matching template to make it available.')
                if pending == 'migration-owned':
                    lines.append('Keep the migration journal. Use cachy-asahi-config-migrate with its original manifest and configuration paths.')
                elif pending in ('blocked', 'unknown'):
                    lines.append('Keep the journal and your edits. Inspect the setup CLI with the same configuration paths before recovery.')
                self.details.set_text('\n'.join(line[:600] for line in lines))
            self.update_buttons()
            return False

        def close_requested(self, *_):
            if self.busy:
                self.closing = True; self.client.cancel.set()
                self.status.set_text('Stopping the helper safely… An interrupted apply may need recovery next time.')
                return True
            return False

    return Window


def main(prefix):
    if not sys.flags.isolated:
        raise bridge.Error('Run the installed isolated launcher.')
    parser = argparse.ArgumentParser(description='Preview activation, removal and recovery of per-user Fish, Zsh and Hyprland settings.')
    for name in ('home', 'template-root', 'config-home', 'zdotdir', 'state-dir'):
        parser.add_argument('--' + name, type=Path)
    args = parser.parse_args()
    client = bridge.Bridge(prefix, **vars(args))
    import gi
    gi.require_version('Gtk', '4.0')
    from gi.repository import Gtk, Gio
    app = Gtk.Application(application_id='io.github.GabrielKahen.CachyAsahiFirstLogin',
                          flags=Gio.ApplicationFlags.NON_UNIQUE)
    Window = window_class()
    def activate(app):
        window = app.get_active_window() or Window(app, client)
        window.present()
    app.connect('activate', activate)
    return app.run([sys.argv[0]])
