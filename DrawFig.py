from matplotlib import pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import pandas as pd
import numpy as np

def draw_server_comp():
    filename = 'measurements.xlsx'
    figname  = 'figs/server3(n=2l=32).pdf'
    df = pd.read_excel(io=filename,sheet_name='server3(n=2l=32)',usecols='A:K')
    df_dict = dict(df)
    x = list(df_dict['d'])

    plt.xlabel('size of model updates', fontdict={'fontsize':15, 'fontweight':'bold'})
    plt.ylabel('running time (s)', fontdict={'fontsize':15, 'fontweight':'bold'})

    share_recovery_key = df.keys()[1]
    y_share_recovery = df_dict[share_recovery_key]
    plt.plot(x, y_share_recovery, '.-', label=share_recovery_key)

    component_wise_bounding_key = df.keys()[2]
    y_component_wise_bounding = df_dict[component_wise_bounding_key]
    plt.plot(x,y_component_wise_bounding,'*-',label=component_wise_bounding_key)

    share_conversion_key = df.keys()[5]
    y_share_conversion = df_dict[share_conversion_key]
    plt.plot(x,y_share_conversion, 'o-',label=share_conversion_key)

    l2_norm_bounding_key = df.keys()[8]
    y_l2_norm_bounding = df_dict[l2_norm_bounding_key]
    plt.plot(x,y_l2_norm_bounding,'^-',label=l2_norm_bounding_key)

    aggregation_key = df.keys()[9]
    y_aggregation = df_dict[aggregation_key]
    plt.plot(x,y_aggregation,'+-',label=aggregation_key)

    total_key = df.keys()[10]
    y_total = df_dict[total_key]
    plt.plot(x,y_total,'x-',label=total_key)

    plt.yticks(size=13, weight='bold')
    plt.xticks(size=13, weight='bold')
    plt.legend(prop={'weight':'bold','size':13})
    plt.grid()
    plt.tight_layout()
    plt.savefig(figname)
    plt.show()

def draw_client_comp():
    filename = 'measurements.xlsx'
    figname  = 'figs/client(n=2l=32).pdf'
    df = pd.read_excel(io=filename,sheet_name='client(n=2l=32)',usecols='A:B')
    df_dict = dict(df)
    x = list(df_dict['d'])

    plt.xlabel('size of model updates', fontdict={'fontsize':15, 'fontweight':'bold'})
    plt.ylabel('running time (s)', fontdict={'fontsize':15, 'fontweight':'bold'})

    share_generation_key = df.keys()[1]
    y_share_generation = df_dict[share_generation_key]
    plt.plot(x, y_share_generation, '.-', label=share_generation_key)

    plt.yticks(size=13, weight='bold')
    plt.xticks(size=13, weight='bold')
    plt.legend(prop={'weight':'bold','size':13})
    plt.grid()
    plt.tight_layout()
    plt.savefig(figname)
    plt.show()
    

def draw_client_comm(): 
    figname = 'figs/comm_client1.pdf'
    # 定义二元函数
    def communication_costs(d, l):
        # unit: MB=#bits/8/1024/1024
        return (2*d*l+4*l)/(8*1024*1024) 
    
    # 生成坐标点
    x = np.linspace(0, 500000, 10000)
    y = np.linspace(0, 64, 8)
    X, Y = np.meshgrid(x, y)
    
    # 计算函数值
    Z = communication_costs(X, Y)
    
    # 绘制图像
    fig = plt.figure(figsize=(10, 8))
    ax = fig.add_subplot(111, projection='3d')
    ax.plot_surface(X, Y, Z, cmap='viridis')
    ax.set_xlabel('size of model updates',fontdict={'fontsize':13,'fontweight':'bold'},labelpad=10)
    ax.set_ylabel('ring size',fontdict={'fontsize':13,'fontweight':'bold'})
    ax.set_zlabel('communication costs (MB)',fontdict={'fontsize':13,'fontweight':'bold'})
    ax.tick_params(axis='x',labelsize=15)
    ax.tick_params(axis='y',labelsize=15)
    ax.tick_params(axis='z',labelsize=15)

    # 获取并设置刻度标签字体加粗
    for label in ax.get_xticklabels():
        label.set_fontweight('bold')
    for label in ax.get_yticklabels():
        label.set_fontweight('bold')
    for label in ax.get_zticklabels():
        label.set_fontweight('bold')    

    # 标记点 x=500000, y=32
    x_point = 500000
    y_point = 32
    z_point = communication_costs(x_point, y_point)  # 计算对应的 Z 值
    ax.scatter(x_point, y_point, z_point, color='blue',s=50,zorder=5)
    ax.text(x_point-60000, y_point, z_point, f'({x_point}, {y_point}, {z_point:.3f})', 
            color='blue', fontsize=10, fontweight='bold',zorder=6)
    x_point = 500000
    y_point = 64
    z_point = communication_costs(x_point, y_point)  # 计算对应的 Z 值
    ax.scatter(x_point, y_point, z_point, color='blue',s=50,zorder=5)
    ax.text(x_point-190000, y_point, z_point-0.7, f'({x_point}, {y_point}, {z_point:.3f})', 
            color='blue', fontsize=10, fontweight='bold')
    plt.savefig(figname)
    plt.show()

def draw_server_comm(): 
    figname = 'figs/comm_server_share_conversion(n=2)1.pdf'
    # 定义二元函数
    def communication_costs_share_conversion(d, l):
        # unit: MB=#bits/8/1024/1024
        return (2 * d * l)/(8 * 1024 * 1024) 
    
    # 生成坐标点
    x = np.linspace(0, 500000, 10000)
    y = np.linspace(0, 64, 8)
    X, Y = np.meshgrid(x, y)
    
    # 计算函数值
    Z = communication_costs_share_conversion(X, Y)
    
    # 绘制图像
    fig = plt.figure(figsize=(10, 8))
    ax = fig.add_subplot(111, projection='3d')
    ax.plot_surface(X, Y, Z, cmap='viridis')
    ax.set_xlabel('size of model updates',fontdict={'fontsize':13,'fontweight':'bold'},labelpad=13)
    ax.set_ylabel('ring size',fontdict={'fontsize':13,'fontweight':'bold'},labelpad=5)
    ax.set_zlabel('communication costs (MB)',fontdict={'fontsize':13,'fontweight':'bold'})
    ax.tick_params(axis='x',labelsize=15)
    ax.tick_params(axis='y',labelsize=15)
    ax.tick_params(axis='z',labelsize=15)

    # 获取并设置刻度标签字体加粗
    for label in ax.get_xticklabels():
        label.set_fontweight('bold')
    for label in ax.get_yticklabels():
        label.set_fontweight('bold')
    for label in ax.get_zticklabels():
        label.set_fontweight('bold')    

    x_point = 500000
    y_point = 32
    z_point = communication_costs_share_conversion(x_point, y_point)  # 计算对应的 Z 值
    ax.scatter(x_point, y_point, z_point, color='blue',s=50,zorder=5)
    ax.text(x_point, y_point, z_point, f'({x_point}, {y_point}, {z_point:.3f})', 
            color='blue', fontsize=10, fontweight='bold',zorder=6)
    x_point = 500000
    y_point = 64
    z_point = communication_costs_share_conversion(x_point, y_point)  # 计算对应的 Z 值
    ax.scatter(x_point, y_point, z_point, color='blue',s=50,zorder=5)
    ax.text(x_point, y_point, z_point, f'({x_point}, {y_point}, {z_point:.3f})', 
            color='blue', fontsize=10, fontweight='bold')
    plt.savefig(figname)
    plt.show()

draw_server_comm()