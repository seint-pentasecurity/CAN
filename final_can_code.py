import math
import pandas as pd
import numpy as np
import matplotlib
#matplotlib.use('Agg')
import matplotlib.animation as animation
import matplotlib.pyplot as plt
import csv

df_with_data = pd.read_csv('../../can_data.csv')

def updateData(self):
	global x
	global yv1
	global t
	global fuz_st
	global fuz_en
	global dos_st
	global dos_en
	global m_pac 
	global m_id
	global dos_state
	global fuz_state
	global id_set
	global prev_pac
	global df_data_dict
	global df_with_data
	global unique_id
	global m_pac_list
	global dos_list 
	global check_pac_index
	global dos_check_time
	global dos_result
	global fuz_result

	df_data_dict[x] = df_with_data[(df_with_data.timestamp >= x) & (df_with_data.timestamp < x + time_interval)]
	tmp_unique_id = df_data_dict[x].groupby(['id1']).count()
	tmp_unique_id = tmp_unique_id[tmp_unique_id.id2 > 3].index.tolist()
	for e in tmp_unique_id:
		if e not in unique_id:
			unique_id.append(e)
	if '0000' not in unique_id:
		unique_id.insert(0, '0000')

######## initial value ########
	t=np.append(t,x)
	x += time_interval
	tmp = df_data_dict[x - time_interval]
	tmpid00 = tmp[tmp.id1 == '0000']
	if x-time_interval == start_time:
		pre_tmp = tmp
		pre_pre_tmp = tmp
		pre_tmpid00 = tmpid00
	elif x-time_interval == start_time+time_interval:
		pre_tmp = df_data_dict[x-time_interval*2]
		pre_pre_tmp = pre_tmp
		pre_tmpid00 = pre_tmp[pre_tmp.id1 == '0000']
	else:
		pre_tmp = df_data_dict[x-time_interval*2]
		pre_pre_tmp = df_data_dict[x-time_interval*3]
		pre_tmpid00 = pre_tmp[pre_tmp.id1 == '0000']
    
######## packet ratio vs time ########
	check_id = -1
	if len(tmp) != 0:
		for i in range(len(unique_id)):
			dpdp[i] = np.append(dpdp[i], len(tmp[tmp.id1 == unique_id[i]]) / len(tmp))
			if dpdp[i][-1] > 0.1:
				p01[i].set_data(t, dpdp[i])#, label = unique_id[i])
				if i == 0:
					p01[i].set_label('0000')
				else:
					p01[i].set_label(unique_id[i])
			else:
				p01[i].set_data(t, dpdp[i])#, label = None)
				if i == 0:
					p01[i].set_label('0000')
				else:
					p01[i].set_label(None)
		for i in range(len(unique_id), 100):
			dpdp[i] = np.append(dpdp[i], 0)
			p01[i].set_data(t, dpdp[i])#, label = ...)
			if i == 0:
				p01[i].set_label('0000')
			else:
				p01[i].set_label(None)
	else:
		for i in range(100):
			dpdp[i] = np.append(dpdp[i], 0)
			p01[i].set_data(t, dpdp[i])#, label = '...')
			if i == 0:
				p01[i].set_label('0000')
			else:
				p01[i].set_label(None)
	ax01.legend()
    
	tmp_dos = tmpid00
	pre_tmp_dos = pre_tmpid00 
	for i in range(len(unique_id)):
		if dpdp[i][-1] > 0.1 and dos_state == 0:          
			pre_tmp_dos_count_list = [0 for i in range(10)]
			tmp_dos = tmp[tmp.id1 == unique_id[i]]
			for j in range(2,12):
				try:
					if len(dos_check_time) > 1:
						if(dos_check_time[1] > x-time_interval*11):
							check_df = df_data_dict[dos_check_time[0]-time_interval*j]
						else:
							check_df = df_data_dict[x-time_interval*j]
					else:
						check_df = df_data_dict[x-time_interval*j]
					pre_tmp_dos_count_list[j-2] = len(check_df[check_df.id1 == unique_id[i]])
				except:
					pre_tmp_dos_count_list[j-2] = len(tmp_dos)
			if unique_id[i] not in dos_list:
				dos_list.append(unique_id[i])
			check_pac_index = dos_list.index(unique_id[i])
			m_pac_list[check_pac_index] = max(pre_tmp_dos_count_list)
    
	if dos_state == 1:
		dos_id = dos_list[check_pac_index]
		tmp_dos = tmp[tmp.id1 == dos_id]
		pre_tmp_dos = pre_tmp[pre_tmp.id1 == dos_id]
    
######## dos attack detect ########
	if fuz_state == 0 and dos_state == 0 and m_pac_list[check_pac_index] * dos_threshold < len(tmp_dos) and len(tmp_dos) > 2:
		tmp_dos_time = tmp_dos.timestamp.values.tolist()
		m_pac = int(math.floor(m_pac_list[check_pac_index]))
		print(m_pac)
		dos_st = tmp_dos_time[m_pac+1]
		dos_check_time = []
		dos_check_time.append(x-time_interval)
		dos_result.append(str(dos_st))
		print('dos attack start time : {}'.format(dos_st))
		dos_state = 1
	elif dos_state == 1 and m_pac >= len(tmp_dos):
		tmp_dos_time = pre_tmp_dos.timestamp.values.tolist()
		dos_en = tmp_dos_time[-m_pac-1]
		dos_result.append(str(dos_en))

		dos_check_time.append(x-time_interval)
		print('dos attack end time : {}'.format(dos_en))
		dos_state = 0

######## fuzzy attack detect ########
	if fuz_state == 0 and m_id > 1 and m_id * st_id_threshold < len(tmp.id1.unique()):
		tmp_fuzzy_id = tmp.id1.values.tolist()
		tmp_fuzzy_time = tmp.timestamp.values.tolist()
		tmp_len_fuzzy = len(tmp_fuzzy_id)
		pre_set = set(pre_tmp.id1.values.tolist())
		pre_pre_set = set(pre_pre_tmp.id1.values.tolist())
		id_set = pre_set | pre_pre_set
		for i in range(tmp_len_fuzzy):
			if tmp_fuzzy_id[i] not in set(id_set|set(unique_id)):
				fuz_st = tmp_fuzzy_time[i]   
				fuz_result.append(str(fuz_st))
				print('fuz attack start time : {}'.format(fuz_st))
				break
		fuz_state = 1
	elif fuz_state == 1 and m_id * en_id_threshold >= len(tmp.id1.unique()):
		tmp_fuzzy_id = pre_tmp.id1.values.tolist()
		tmp_fuzzy_time = pre_tmp.timestamp.values.tolist()
		tmp_len_fuzzy = len(tmp_fuzzy_id)
		id_set = id_set | (set(tmp.id1.values.tolist()))
		for i in range(tmp_len_fuzzy-1,-1,-1):
			if tmp_fuzzy_id[i] not in set(id_set|set(unique_id)):
				fuz_en = tmp_fuzzy_time[i]
				fuz_result.append(str(fuz_en))
				print('fuz attack end time : {}'.format(fuz_en))
				break
		fuz_state = 0
	elif fuz_state == 0:
		m_id = max(m_id, len(tmp.id1.unique()))

######## unique id number vs time ########
	if len(tmp) == 0:
		yv1=np.append(yv1, 0)
	else:
		yv1=np.append(yv1, len(tmp.id1.unique()))
	p021.set_data(t, yv1)


######## setting x domain limit ########
	if x >= xmax-time_interval:
		p01[0].axes.set_xlim(x-2*xmax+time_interval,x+time_interval)
		p021.axes.set_xlim(x-2*xmax+time_interval,x+time_interval)
        
        

start_time = 1479109900

font = {'size'   : 9}
matplotlib.rc('font', **font)

f0 = plt.figure(num = 0, figsize = (12, 8))
f0.suptitle("Dos-Fuzzy Attack Detection", fontsize=12)
ax01 = plt.subplot2grid((2, 1), (0, 0))
ax02 = plt.subplot2grid((2, 1), (1, 0))
# tight_layout()

# Set titles of subplots
ax01.set_title('Id_Ratio vs Time')
ax02.set_title('Unique_Id_Number vs Time')

# set y-limits
ax01.set_ylim(0,1)
ax02.set_ylim(0,300)

# sex x-limits
ax01.set_xlim(0,2)
ax02.set_xlim(0,2)

# Turn on grids
ax01.grid(True)
ax02.grid(True)

# set label names
ax01.set_xlabel("Time")
ax01.set_ylabel("Id[%]")
ax02.set_xlabel("Time")
ax02.set_ylabel("Unique_Id")

# Data Placeholders
yv1=np.zeros(0)
t=np.zeros(0)

dpdp = []
for i in range(100):
    dpdp.append(np.zeros(0))

p01 = []
for i in range(100):
    tmp, = ax01.plot(t, dpdp[i], label=None)
    p01.append(tmp)

p021, = ax02.plot(t,yv1,'b-')

#set lagends
#ax01.legend(p01, unique_id).set_alpha(0.4)
#ax01.legend()


# Data Update
xmin = 0.0
xmax = 2.0
# start_time = 1479109900
x = start_time
df_data_dict = {}
time_interval = 0.25
#doubt dos attack #1479111730

unique_id = []
pac_threshold = 1.2
dos_threshold = 2
st_id_threshold = 1.3
en_id_threshold = 1.1
dos_check_time = []

id_set = set([])
tmp = df_with_data[(df_with_data.timestamp >= x) & (df_with_data.timestamp < x + time_interval)]
prev_pac = 0

m_pac_list = [0 for i in range(10)]
m_id = len(tmp.id1.unique())
if m_id == 0:
    m_id = 1

dos_list = []
dos_st = -1
dos_en = -1
fuz_st = -1
fuz_en = -1
dos_state = 0
fuz_state = 0
fuz_result = []
dos_result = []
check_pac_index = 0

######## animation function ########
# interval: draw new frame every 'interval' ms
# frames: number of frames to draw
simulation = animation.FuncAnimation(f0, updateData, blit=False, frames = 16000, interval=1, repeat=False)


# fname = './test1124_dos{}' %
# Uncomment the next line if you want to save the animation
# simulation.save(filename=fname, writer='imagemagick' , fps=4,dpi=300) #writer='ffmpeg'

# matplotlib.pyplot.show()
plt.show()


######
final_dos_result = []
for i in range(0, len(dos_result), 2):
	final_dos_result.append([dos_result[i], dos_result[i+1], 'DoS'])

for i in range(0, len(fuz_result), 2):
	final_dos_result.append([fuz_result[i], fuz_result[i+1], 'Fuzzy'])

df = pd.DataFrame(final_dos_result, columns = ['start_time', 'end_time', 'attack'])
df = df.sort_values(by = 'start_time')
df.to_csv('./result_car_seint.csv', index=None)


