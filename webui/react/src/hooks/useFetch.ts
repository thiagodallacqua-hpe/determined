import { useCallback } from 'react';

import { activeRunStates } from 'constants/states';
import { StoreAction, useStoreDispatch } from 'contexts/Store';
import {
  getActiveTasks,
  getExperiments,
  getInfo,
  getPermissionsSummary,
  getResourcePools,
  getUsers,
  getWorkspaces,
  listRoles,
} from 'services/api';
import { ErrorType } from 'shared/utils/error';
import handleError from 'utils/error';

export const useFetchActiveExperiments = (canceler: AbortController): (() => Promise<void>) => {
  const storeDispatch = useStoreDispatch();

  return useCallback(async (): Promise<void> => {
    try {
      const response = await getExperiments(
        { limit: -2, states: activeRunStates },
        { signal: canceler.signal },
      );
      storeDispatch({
        type: StoreAction.SetActiveExperiments,
        value: response.pagination.total || 0,
      });
    } catch (e) {
      handleError({
        message: 'Unable to fetch active experiments.',
        silent: true,
        type: ErrorType.Api,
      });
    }
  }, [canceler, storeDispatch]);
};

export const useFetchInfo = (canceler: AbortController): (() => Promise<void>) => {
  const storeDispatch = useStoreDispatch();

  return useCallback(async (): Promise<void> => {
    try {
      const response = await getInfo({ signal: canceler.signal });
      storeDispatch({ type: StoreAction.SetInfo, value: response });
    } catch (e) {
      storeDispatch({ type: StoreAction.SetInfoCheck });
      handleError(e);
    }
  }, [canceler, storeDispatch]);
};

export const useFetchUsers = (canceler: AbortController): (() => Promise<void>) => {
  const storeDispatch = useStoreDispatch();

  return useCallback(async (): Promise<void> => {
    try {
      const usersResponse = await getUsers({}, { signal: canceler.signal });
      storeDispatch({ type: StoreAction.SetUsers, value: usersResponse.users });
    } catch (e) {
      handleError(e);
    }
  }, [canceler, storeDispatch]);
};

export const useFetchResourcePools = (canceler?: AbortController): (() => Promise<void>) => {
  const storeDispatch = useStoreDispatch();
  return useCallback(async (): Promise<void> => {
    try {
      const resourcePools = await getResourcePools({}, { signal: canceler?.signal });
      storeDispatch({ type: StoreAction.SetResourcePools, value: resourcePools });
    } catch (e) {
      handleError(e);
    }
  }, [canceler, storeDispatch]);
};

export const useFetchActiveTasks = (canceler: AbortController): (() => Promise<void>) => {
  const storeDispatch = useStoreDispatch();

  return useCallback(async (): Promise<void> => {
    try {
      const counts = await getActiveTasks({}, { signal: canceler.signal });
      storeDispatch({ type: StoreAction.SetActiveTasks, value: counts });
    } catch (e) {
      handleError({ message: 'Unable to fetch task counts.', silent: true, type: ErrorType.Api });
    }
  }, [canceler, storeDispatch]);
};

export const useFetchPinnedWorkspaces = (canceler: AbortController): (() => Promise<void>) => {
  const storeDispatch = useStoreDispatch();
  return useCallback(async (): Promise<void> => {
    try {
      const pinnedWorkspaces = await getWorkspaces(
        { limit: 0, pinned: true },
        { signal: canceler.signal },
      );
      storeDispatch({ type: StoreAction.SetPinnedWorkspaces, value: pinnedWorkspaces.workspaces });
    } catch (e) {
      handleError(e);
    }
  }, [canceler, storeDispatch]);
};

export const useFetchKnownRoles = (canceler: AbortController): (() => Promise<void>) => {
  const storeDispatch = useStoreDispatch();
  return useCallback(async (): Promise<void> => {
    try {
      const roles = await listRoles({ limit: 0 }, { signal: canceler.signal });
      storeDispatch({ type: StoreAction.SetKnownRoles, value: roles });
    } catch (e) {
      handleError(e);
    }
  }, [canceler, storeDispatch]);
};

export const useFetchMyRoles = (canceler: AbortController): (() => Promise<void>) => {
  const storeDispatch = useStoreDispatch();
  return useCallback(async (): Promise<void> => {
    try {
      const { assignments, roles } = await getPermissionsSummary(
        { limit: 0 },
        { signal: canceler.signal },
      );
      storeDispatch({ type: StoreAction.SetUserRoles, value: roles });
      storeDispatch({ type: StoreAction.SetUserAssignments, value: assignments });
    } catch (e) {
      handleError(e);
    }
  }, [canceler, storeDispatch]);
};
