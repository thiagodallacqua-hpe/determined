import { Meta, Story } from '@storybook/react';
import { array, number, string, undefined, union } from 'io-ts';
import React, { useCallback, useMemo, useRef } from 'react';

import { SettingsConfig, useSettings } from 'hooks/useSettings';
import { generateAlphaNumeric, generateLetters } from 'shared/utils/string';

import InteractiveTable, { InteractiveTableSettings } from './InteractiveTable';

export default {
  argTypes: {
    numRows: { control: { max: 100, min: 0, step: 5, type: 'range' } },
    size: { control: { options: ['default', 'middle', 'small'], type: 'inline-radio' } },
  },
  component: InteractiveTable,
  parameters: { layout: 'padded' },
  title: 'Determined/Tables/InteractiveTable',
} as Meta<typeof InteractiveTable>;

const DEFAULT_COLUMN_WIDTH = 150;

const columns = new Array(20).fill(null).map(() => {
  const str = generateLetters();
  return {
    dataIndex: str,
    defaultWidth: DEFAULT_COLUMN_WIDTH,
    sorter: true,
    title: str,
  };
});

const config: SettingsConfig<Omit<InteractiveTableSettings, 'sortDesc' | 'sortKey' | 'tableLimit' | 'tableOffset'>> = {
  applicableRoutespace: 'storybook',
  settings: {
    columns: {
      defaultValue: columns.map((column) => column.dataIndex),
      storageKey: 'columns',
      type: {
        baseType: array(string),
        isArray: true,
      },
    },
    columnWidths: {
      defaultValue: columns.map((column) => column.defaultWidth),
      skipUrlEncoding: true,
      storageKey: 'columnWidths',
      type: {
        baseType: array(number),
        isArray: true,
      },
    },
    row: {
      defaultValue: [],
      storageKey: 'row',
      type: { baseType: union([undefined, array(string), array(number)]), isArray: true },
    },
  },
  storagePath: 'storybook',
};

type InteractiveTableProps = React.ComponentProps<typeof InteractiveTable>;

export const Default: Story<InteractiveTableProps & { numRows: number }> = ({
  numRows,
  ...args
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const { settings, updateSettings } = useSettings<Omit<InteractiveTableSettings, 'sortDesc' | 'sortKey' | 'tableLimit' | 'tableOffset'>>(config);

  const handleTableRowSelect = useCallback(
    (rowKeys) => {
      updateSettings({ row: rowKeys });
    },
    [updateSettings],
  );

  const data = useMemo(() => {
    return new Array(numRows).fill(null).map(() => {
      const row: Record<string, string> = {};
      columns.forEach((column) => {
        row[column.dataIndex] = generateAlphaNumeric();
      });
      return row;
    });
  }, [numRows]);

  return (
    <div ref={containerRef}>
      <InteractiveTable
        {...args}
        areRowsSelected={!!settings.row}
        columns={columns}
        containerRef={containerRef}
        dataSource={data}
        rowKey={columns[0].title}
        rowSelection={{
          onChange: handleTableRowSelect,
          preserveSelectedRowKeys: true,
          selectedRowKeys: settings.row ?? [],
        }}
        settings={settings as InteractiveTableSettings}
        updateSettings={updateSettings}
      />
    </div>
  );
};

Default.args = { numRows: 50, showSorterTooltip: false, size: 'small' };