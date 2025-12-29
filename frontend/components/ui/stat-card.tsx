"use client";

import { cn } from "@/lib/utils";
import { Card, CardContent } from "@/components/ui/card";
import { TrendingUp, TrendingDown, Minus } from "lucide-react";

type ColorVariant = "default" | "blue" | "green" | "amber" | "purple" | "rose";

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon?: React.ReactNode;
  trend?: {
    value: number;
    label: string;
  };
  color?: ColorVariant;
  className?: string;
}

// Enterprise design: monochromatic with status-based colors only
const colorStyles: Record<ColorVariant, { iconBg: string; iconText: string; valueColor: string }> = {
  default: {
    iconBg: "bg-slate-100",
    iconText: "text-slate-600",
    valueColor: "text-slate-900",
  },
  blue: {
    iconBg: "bg-indigo-100",
    iconText: "text-indigo-600",
    valueColor: "text-slate-900",
  },
  green: {
    iconBg: "bg-emerald-100",
    iconText: "text-emerald-600",
    valueColor: "text-emerald-600", // Status: healthy
  },
  amber: {
    iconBg: "bg-amber-100",
    iconText: "text-amber-600",
    valueColor: "text-amber-600", // Status: warning
  },
  purple: {
    iconBg: "bg-indigo-100",
    iconText: "text-indigo-600",
    valueColor: "text-slate-900",
  },
  rose: {
    iconBg: "bg-rose-100",
    iconText: "text-rose-600",
    valueColor: "text-rose-600", // Status: critical
  },
};

export function StatCard({
  title,
  value,
  subtitle,
  icon,
  trend,
  color = "default",
  className,
}: StatCardProps) {
  const styles = colorStyles[color];
  const getTrendIcon = () => {
    if (!trend) return null;
    if (trend.value > 0) {
      return <TrendingUp className="h-3 w-3 text-green-500" />;
    } else if (trend.value < 0) {
      return <TrendingDown className="h-3 w-3 text-red-500" />;
    }
    return <Minus className="h-3 w-3 text-slate-400" />;
  };

  const getTrendColor = () => {
    if (!trend) return "";
    if (trend.value > 0) return "text-green-600";
    if (trend.value < 0) return "text-red-600";
    return "text-slate-500";
  };

  return (
    <Card className={cn("bg-white shadow-sm hover:shadow-md transition-shadow border border-slate-200/60", className)}>
      <CardContent className="pt-5 pb-5">
        <div className="flex items-center justify-between">
          <div className="space-y-1">
            <p className="text-sm font-medium text-slate-500">{title}</p>
            <p className={cn("text-2xl font-semibold tracking-tight", styles.valueColor)}>{value}</p>
            {subtitle && (
              <p className="text-sm text-slate-400">{subtitle}</p>
            )}
            {trend && (
              <div className={cn("flex items-center gap-1 text-sm", getTrendColor())}>
                {getTrendIcon()}
                <span>
                  {trend.value > 0 ? "+" : ""}
                  {trend.value}% {trend.label}
                </span>
              </div>
            )}
          </div>
          {icon && (
            <div className={cn("h-10 w-10 rounded-lg flex items-center justify-center", styles.iconBg, styles.iconText)}>
              {icon}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
