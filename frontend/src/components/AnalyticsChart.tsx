import React from "react";
import { Bar } from "react-chartjs-2";
import {
    Chart as ChartJS,
    CategoryScale,
    LinearScale,
    BarElement,
    Title,
    Tooltip,
    Legend,
    ChartOptions,
} from "chart.js";

ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

type AnalyticsChartProps = {
    labels: string[];
    data: number[];
    title: string;
};

const AnalyticsChart: React.FC<AnalyticsChartProps> = ({ labels, data, title }) => {
    const chartData = {
        labels,
        datasets: [
            {
                label: title,
                data,
                backgroundColor: "rgba(75, 192, 192, 0.6)",
                borderColor: "rgba(75, 192, 192, 1)",
                borderWidth: 1,
            },
        ],
    };

    // Explicitly define the options type using ChartOptions for "bar"
    const options: ChartOptions<"bar"> = {
        responsive: true,
        plugins: {
            legend: {
                position: "top", // Ensure this matches one of the accepted values
            },
            title: {
                display: true,
                text: title,
            },
        },
    };

    return <Bar data={chartData} options={options} />;
};

export default AnalyticsChart;
