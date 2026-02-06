'use client';

export interface DataReadoutProps {
  label: string;
  value: React.ReactNode;
  valueColor?: string;
  suffix?: string;
}

export function DataReadout({ label, value, valueColor, suffix }: DataReadoutProps) {
  return (
    <div className="c2-readout">
      <div className="c2-readout__label">{label}</div>
      <div className="c2-readout__value" style={valueColor ? { color: valueColor } : undefined}>
        {value}
        {suffix != null && <span className="c2-readout__suffix">{suffix}</span>}
      </div>
    </div>
  );
}
