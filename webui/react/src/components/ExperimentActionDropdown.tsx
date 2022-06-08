import { ExclamationCircleOutlined } from '@ant-design/icons';
import { Dropdown, Menu, Modal } from 'antd';
import { MenuInfo } from 'rc-menu/lib/interface';
import React, { PropsWithChildren, useCallback, useEffect, useState } from 'react';

import useModalExperimentCreate,
{ CreateExperimentType } from 'hooks/useModal/useModalExperimentCreate';
import useModalExperimentMove from 'hooks/useModal/useModalExperimentMove';
import { handlePath, paths } from 'routes/utils';
import {
  activateExperiment,
  archiveExperiment,
  cancelExperiment,
  deleteExperiment,
  getExperimentDetails,
  getTrialDetails,
  killExperiment,
  openOrCreateTensorBoard,
  pauseExperiment,
  unarchiveExperiment,
} from 'services/api';
import css from 'shared/components/ActionDropdown/ActionDropdown.module.scss';
import Icon from 'shared/components/Icon/Icon';
import { ErrorLevel, ErrorType } from 'shared/utils/error';
import { capitalize } from 'shared/utils/string';
import {
  ExperimentAction as Action, DetailedUser, ExperimentBase, ProjectExperiment,
} from 'types';
import handleError from 'utils/error';
import {
  getActionsForExperiment,
} from 'utils/experiment';
import { openCommand } from 'wait';

interface Props {
  curUser?: DetailedUser;
  experiment: ProjectExperiment;
  onComplete?: (action?: Action) => void;
  onVisibleChange?: (visible: boolean) => void;
  workspaceId?: number;
}

const dropdownActions = [
  Action.Activate,
  Action.Pause,
  Action.Archive,
  Action.Unarchive,
  Action.Cancel,
  Action.Fork,
  Action.DownloadCode,
  Action.ContinueTrial,
  Action.Kill,
  Action.Delete,
  Action.Move,
  Action.OpenTensorBoard,
];

const stopPropagation = (e: React.MouseEvent): void => e.stopPropagation();

const ExperimentActionDropdown: React.FC<Props> = ({
  experiment,
  onComplete,
  curUser,
  onVisibleChange,
  children,
}: PropsWithChildren<Props>) => {
  const id = experiment.id;
  const [ canceler ] = useState(new AbortController());
  const [ fullExperiment, setFullExperiment ] = useState<ExperimentBase>();
  const { modalOpen: openModalCreate } = useModalExperimentCreate();
  const { modalOpen: openExperimentMove } = useModalExperimentMove({ onClose: onComplete });
  const trialId = experiment.trialIds?.[0];

  useEffect(() => {
    (async () => {
      const exp = await getExperimentDetails(
        { id: experiment.id },
        { signal: canceler.signal },
      );

      setFullExperiment(exp);
    })();

    return () => {
      setFullExperiment(undefined);
    };
  }, [ canceler, experiment.id ]);

  const handleExperimentMove = useCallback(() => {
    openExperimentMove({
      experimentIds: experiment.id ? [ experiment.id ] : undefined,
      sourceProjectId: experiment.projectId,
      sourceWorkspaceId: experiment.workspaceId,
    });
  }, [ openExperimentMove, experiment.id, experiment.projectId, experiment.workspaceId ]);

  const handleExperimentFork = useCallback(() => {
    if(fullExperiment)
      openModalCreate({ experiment: fullExperiment, type: CreateExperimentType.Fork });
  }, [ fullExperiment, openModalCreate ]);

  const handleContinueTrial = useCallback(async () => {
    if (fullExperiment && trialId) {
      const trial = await getTrialDetails({ id: trialId });

      openModalCreate({
        experiment: fullExperiment,
        trial,
        type: CreateExperimentType.ContinueTrial,
      });
    }
  }, [ fullExperiment, openModalCreate, trialId ]);

  const handleMenuClick = async (params: MenuInfo): Promise<void> => {
    const e = params.domEvent as React.MouseEvent<HTMLElement, MouseEvent>;
    params.domEvent.stopPropagation();
    try {
      const action = params.key as Action;
      switch (action) { // Cases should match menu items.
        case Action.Activate:
          await activateExperiment({ experimentId: id });
          if (onComplete) onComplete(action);
          break;
        case Action.Archive:
          await archiveExperiment({ experimentId: id });
          if (onComplete) onComplete(action);
          break;
        case Action.Cancel:
          await cancelExperiment({ experimentId: id });
          if (onComplete) onComplete(action);
          break;
        case Action.OpenTensorBoard: {
          const tensorboard = await openOrCreateTensorBoard({ experimentIds: [ id ] });
          openCommand(tensorboard);
          break;
        }
        case Action.Kill:
          Modal.confirm({
            content: `
              Are you sure you want to kill
              experiment ${id}?
            `,
            icon: <ExclamationCircleOutlined />,
            okText: 'Kill',
            onOk: async () => {
              await killExperiment({ experimentId: id });
              onComplete?.(action);
            },
            title: 'Confirm Experiment Kill',
          });
          break;
        case Action.Pause:
          await pauseExperiment({ experimentId: id });
          if (onComplete) onComplete(action);
          break;
        case Action.Unarchive:
          await unarchiveExperiment({ experimentId: id });
          if (onComplete) onComplete(action);
          break;
        case Action.Delete:
          Modal.confirm({
            content: `
            Are you sure you want to delete
            experiment ${id}?
          `,
            icon: <ExclamationCircleOutlined />,
            okText: 'Delete',
            onOk: async () => {
              await deleteExperiment({ experimentId: id });
              if (onComplete) onComplete(action);
            },
            title: 'Confirm Experiment Deletion',
          });
          break;
        case Action.Move:
          handleExperimentMove();
          break;
        case Action.ContinueTrial:
          if (trialId) {
            await handleContinueTrial();
          }

          break;
        case Action.DownloadCode:
          handlePath(e, { external: true, path: paths.experimentModelDef(experiment.id) });
          break;
        case Action.Fork:
          await handleExperimentFork();
          break;
      }
    } catch (e) {
      handleError(e, {
        level: ErrorLevel.Error,
        publicMessage: `Unable to ${params.key} experiment ${experiment.id}.`,
        publicSubject: `${capitalize(params.key.toString())} failed.`,
        silent: false,
        type: ErrorType.Server,
      });
    } finally {
      onVisibleChange?.(false);
    }
    // TODO show loading indicator when we have a button component that supports it.
  };

  const menuItems = getActionsForExperiment(experiment, dropdownActions, curUser).map((action) => (
    <Menu.Item danger={action === Action.Delete} key={action}>
      {action}
    </Menu.Item>
  ));

  if (menuItems.length === 0) {
    return (children as JSX.Element) ?? (
      <div className={css.base} title="No actions available" onClick={stopPropagation}>
        <button disabled>
          <Icon name="overflow-vertical" />
        </button>
      </div>
    );
  }

  const menu = <Menu onClick={handleMenuClick}>{menuItems}</Menu>;

  return children ? (
    <Dropdown
      overlay={menu}
      placement="bottomLeft"
      trigger={[ 'contextMenu' ]}
      onVisibleChange={onVisibleChange}>
      {children}
    </Dropdown>
  ) : (
    <div className={css.base} title="Open actions menu" onClick={stopPropagation}>
      <Dropdown overlay={menu} placement="bottomRight" trigger={[ 'click' ]}>
        <button onClick={stopPropagation}>
          <Icon name="overflow-vertical" />
        </button>
      </Dropdown>
    </div>
  );
};

export default ExperimentActionDropdown;
