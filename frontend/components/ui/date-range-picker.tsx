"use client";

import { useState } from "react";
import { Calendar, ChevronDown } from "lucide-react";
import { cn } from "@/lib/utils";

interface DateRangePickerProps {
  startDate: string;
  endDate: string;
  onChange: (start: string, end: string) => void;
  className?: string;
}

const presets = [
  { label: "Today", days: 0 },
  { label: "Last 7 days", days: 7 },
  { label: "Last 30 days", days: 30 },
  { label: "Last 90 days", days: 90 },
];

export function DateRangePicker({
  startDate,
  endDate,
  onChange,
  className,
}: DateRangePickerProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [localStart, setLocalStart] = useState(startDate);
  const [localEnd, setLocalEnd] = useState(endDate);

  const formatDateDisplay = (start: string, end: string) => {
    if (!start && !end) return "All time";
    const startFormatted = start ? new Date(start).toLocaleDateString() : "Start";
    const endFormatted = end ? new Date(end).toLocaleDateString() : "End";
    return `${startFormatted} - ${endFormatted}`;
  };

  const handlePreset = (days: number) => {
    const end = new Date();
    const start = new Date();
    start.setDate(start.getDate() - days);

    const startStr = start.toISOString().split("T")[0];
    const endStr = end.toISOString().split("T")[0];

    setLocalStart(startStr);
    setLocalEnd(endStr);
    onChange(startStr, endStr);
    setIsOpen(false);
  };

  const handleApply = () => {
    onChange(localStart, localEnd);
    setIsOpen(false);
  };

  const handleClear = () => {
    setLocalStart("");
    setLocalEnd("");
    onChange("", "");
    setIsOpen(false);
  };

  return (
    <div className={cn("relative", className)}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-3 py-2 border rounded-lg text-sm hover:bg-slate-50 transition-colors"
      >
        <Calendar className="h-4 w-4 text-slate-500" />
        <span>{formatDateDisplay(startDate, endDate)}</span>
        <ChevronDown className={cn("h-4 w-4 text-slate-500 transition-transform", isOpen && "rotate-180")} />
      </button>

      {isOpen && (
        <>
          <div
            className="fixed inset-0 z-40"
            onClick={() => setIsOpen(false)}
          />
          <div className="absolute top-full right-0 mt-2 z-50 bg-white border rounded-lg shadow-lg p-4 min-w-[300px]">
            {/* Presets */}
            <div className="flex flex-wrap gap-2 mb-4">
              {presets.map((preset) => (
                <button
                  key={preset.label}
                  onClick={() => handlePreset(preset.days)}
                  className="px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-100 hover:bg-slate-200 transition-colors"
                >
                  {preset.label}
                </button>
              ))}
            </div>

            {/* Custom Range */}
            <div className="space-y-3">
              <div>
                <label className="text-xs font-medium text-slate-600">Start Date</label>
                <input
                  type="date"
                  value={localStart}
                  onChange={(e) => setLocalStart(e.target.value)}
                  className="w-full mt-1 px-3 py-2 border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
                />
              </div>
              <div>
                <label className="text-xs font-medium text-slate-600">End Date</label>
                <input
                  type="date"
                  value={localEnd}
                  onChange={(e) => setLocalEnd(e.target.value)}
                  className="w-full mt-1 px-3 py-2 border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
                />
              </div>
            </div>

            {/* Actions */}
            <div className="flex justify-between mt-4 pt-4 border-t">
              <button
                onClick={handleClear}
                className="text-sm text-slate-500 hover:text-slate-700"
              >
                Clear
              </button>
              <button
                onClick={handleApply}
                className="px-4 py-1.5 text-sm font-medium bg-slate-900 text-white rounded-lg hover:bg-slate-800 transition-colors"
              >
                Apply
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
