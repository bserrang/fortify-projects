import {
  shell,
  MenuItemConstructorOptions,
} from 'electron';
import { l10n } from '../l10n';
import { TOOLS_LINK } from '../constants';
import { windowsController } from '../windows';

export const baseTemplate = (): MenuItemConstructorOptions[] => ([
  {
    label: l10n.get('about'),
    click: () => {
      windowsController.showAboutWindow();
    },
  },
  {
    label: l10n.get('settings'),
    click: () => {
      windowsController.showSettingsWindow();
    },
  },
  {
    type: 'separator',
  },
  {
    label: l10n.get('tools'),
    click: () => {
      shell.openExternal(TOOLS_LINK);
    },
  },
  {
    label: l10n.get('exit'),
    role: 'quit',
  },
]);
