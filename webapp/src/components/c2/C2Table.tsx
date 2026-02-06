'use client';

import { Table, type TableProps } from 'antd';

export interface C2TableProps<RecordType> extends TableProps<RecordType> {
  /** Optional; if you need a wrapper with C2 table class only, use className="c2-table" on Table */
}

export function C2Table<RecordType extends object>(props: C2TableProps<RecordType>) {
  return (
    <div className="c2-table-wrap">
      <Table<RecordType> className="c2-table" {...props} />
    </div>
  );
}
