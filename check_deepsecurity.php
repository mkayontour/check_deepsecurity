<?php
#
# PNP4Nagios Template for check_deepsecurity plugin
#
# COPYRIGHT:
# 
# This software is Copyright (c) 2015 NETWAYS GmbH, Dirk Götz
#                                <support@netways.de>
#
# LICENSE:
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
# or see <http://www.gnu.org/licenses/>.
#
# CONTRIBUTION SUBMISSION POLICY:
#
# (The following paragraph is not intended to limit the rights granted
# to you to modify and distribute this software under the terms of
# the GNU General Public License and is only of importance to you if
# you choose to contribute your changes and enhancements to the
# community by submitting them to NETWAYS GmbH.)
#
# By intentionally submitting any modifications, corrections or
# derivatives to this work, or any other work intended for use with
# this Software, to NETWAYS GmbH, you confirm that
# you are the copyright holder for those contributions and you grant
# NETWAYS GmbH a nonexclusive, worldwide, irrevocable,
# royalty-free, perpetual, license to use, copy, create derivative
# works based on those contributions, and sublicense and distribute
# those contributions and any derivatives thereof.
#
# RRDtool Options
$opt[1] = "-l 0 --title \"Deepsecurity Status\" ";
#
#
# Graph Definitions
# Variablen: critical, warning, managed, unmanaged
$def[1] =  "DEF:var1=$rrdfile:1:AVERAGE "; 
$def[1] .= "DEF:var2=$rrdfile:2:AVERAGE "; 
$def[1] .= "DEF:var3=$rrdfile:3:AVERAGE "; 
$def[1] .= "DEF:var4=$rrdfile:4:AVERAGE "; 

# Totals
$def[1] .= "CDEF:tot=var1,var2,+,var3,+,var4,+ ";

# Graphen: managed, unmanaged, warning, critical
$def[1] .= "AREA:var3#00FF00:managed ";
$def[1] .= "LINE1:0#008000::STACK ";
$def[1] .= "AREA:var2#FFFF00:warning:STACK ";
$def[1] .= "LINE1:0#808000::STACK ";
$def[1] .= "AREA:var4#d6d6d6:unmanaged:STACK ";
$def[1] .= "LINE1:0#565656::STACK ";
$def[1] .= "AREA:var1#FF0000:critical\j:STACK ";
$def[1] .= "LINE1:0#800000::STACK ";

# Legende
$def[1] .= "GPRINT:var1:LAST:\"%.lf critical \" ";
$def[1] .= "GPRINT:var2:LAST:\"%.lf warning \" ";
$def[1] .= "GPRINT:var3:LAST:\"%.lf managed \" ";
$def[1] .= "GPRINT:var4:LAST:\"%.lf unmanaged \" ";
$def[1] .= "GPRINT:tot:LAST:\"%.lf total \" ";
?>
