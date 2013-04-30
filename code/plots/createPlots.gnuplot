########## CONSTANT DATA ##########
# Divergence Constant Graph
#set surface
set title "KL-Divergence -- Constant Add/Drop Rates"
set xlabel "Packet Add Rate" offset -3, -1
set ylabel "Packet Drop Rate" 3,-1
set zlabel "KL-Divergence" offset 10,5
set pm3d
set term png
set output "./divergence_constant_plot.png"
splot './divergence_constant_plot.data' with lines
#pause -1

# Time graph for constant data
set title "Simulation Finish Time (seconds) -- Constant Add/Drop Rates"
set xlabel "Packet Add Rate" offset -3, -1
set ylabel "Packet Drop Rate" 3,-1
set zlabel "Total Time (s)" offset 10,5
set pm3d
set term png
set output "./time_constant_plot.png"
splot './time_constant_plot.data' with lines

# Total Packets Graph For Constant Data
set title "Total Packets in Simulation -- Constant Add/Drop Rates"
set xlabel "Packet Add Rate" offset -3, -1
set ylabel "Packet Drop Rate" 3,-1
set zlabel "Packet Count" offset 10,5
set pm3d
set term png
set output "./totalPackets_constant_plot.png"
splot './totalPackets_constant_plot.data' with lines

# Divergence Percent Graph
#set surface
set title "KL-Divergence Percent Increase -- Constant Add/Drop Rates"
set xlabel "Packet Add Rate" offset -3, -1
set ylabel "Packet Drop Rate" 3,-1
set zlabel "Percent Increase" offset 10,5
set pm3d
set term png
set output "./divergence_perc_constant_plot.png"
splot './divergence_perc_constant_plot.data' with lines
#pause -1

# PERCENT INCREASE Time graph for constant data
set title "Percentage Increase in Simulation Finish Time (seconds) -- Constant Add/Drop Rates"
set xlabel "Packet Add Rate" offset -3, -1
set ylabel "Packet Drop Rate" 3,-1
set zlabel "Percent Increase" offset 10,5
set pm3d
set term png
set output "./time_perc_constant_plot.png"
splot './time_perc_constant_plot.data' with lines

# Total Packets Graph For Constant Data
set title "Percent Increase of Total Packets in Simulation -- Constant Add/Drop Rates"
set xlabel "Packet Add Rate" offset -3, -1
set ylabel "Packet Drop Rate" 3,-1
set zlabel "Percent Increase" offset 10,5
set pm3d
set term png
set output "./totalPackets_perc_constant_plot.png"
splot './totalPackets_perc_constant_plot.data' with lines


######### VARIED DATA ###########

# Varied - Divergence  
#set hidden3
#set surface
set title "KL-Divergence -- Varied Add/Drop Rates"
set xlabel "Packet Add Rate" offset -3, -1
set ylabel "Packet Drop Rate" 3,-1
set zlabel "KL-Divergence" offset 10,5
set pm3d
set term png
set output "divergence_varied_plot.png"
splot './divergence_varied_plot.data' with lines
#pause -1

# Time graph for variedant data
set title "Simulation Finish Time -- Varied Add/Drop Rates"
set xlabel "Packet Add Rate" offset -3, -1
set ylabel "Packet Drop Rate" 3,-1
set zlabel "Total Time (s)" offset 10,5
set pm3d
set term png
set output "./time_varied_plot.png"
splot './time_varied_plot.data' with lines

# Total Packets Graph For Constant Data
set title "Total Packets in Simulation -- Varied Add/Drop Rates"
set xlabel "Packet Add Rate" offset -3, -1
set ylabel "Packet Drop Rate" 3,-1
set zlabel "Packet Count" offset 10,5
set pm3d
set term png
set output "./totalPackets_varied_plot.png"
splot './totalPackets_varied_plot.data' with lines

# Varied- Divergence Percent Graph
#set surface
set title "KL-Divergence Percent Increase -- Varied Add/Drop Rates"
set xlabel "Packet Add Rate" offset -3, -1
set ylabel "Packet Drop Rate" 3,-1
set zlabel "Percent Increase" offset 10,5
set pm3d
set term png
set output "./divergence_perc_varied_plot.png"
splot './divergence_perc_varied_plot.data' with lines
#pause -1

# PERCENT INCREASE Time graph for varied data
set title "Percentage Increase in Simulation Finish Time (seconds) -- Varied Add/Drop Rates"
set xlabel "Packet Add Rate" offset -3, -1
set ylabel "Packet Drop Rate" 3,-1
set zlabel "Percent Increase" offset 10,5
set pm3d
set term png
set output "./time_perc_varied_plot.png"
splot './time_perc_varied_plot.data' with lines

# Total Packets Graph For Constant Data
set title "Percent Increase of Total Packets in Simulation -- Varied Add/Drop Rates"
set xlabel "Packet Add Rate" offset -3, -1
set ylabel "Packet Drop Rate" 3,-1
set zlabel "Percent Increase" offset 10,5
set pm3d
set term png
set output "./totalPackets_perc_varied_plot.png"
splot './totalPackets_perc_varied_plot.data' with lines
