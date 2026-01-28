
// Description: Java 25 in-memory RAM DbIO implementation for Service.

/*
 *	io.github.msobkow.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	This file is part of Mark's Code Fractal CFSec.
 *	
 *	Mark's Code Fractal CFSec is available under dual commercial license from
 *	Mark Stephen Sobkow, or under the terms of the GNU Library General Public License,
 *	Version 3 or later.
 *	
 *	Mark's Code Fractal CFSec is free software: you can redistribute it and/or
 *	modify it under the terms of the GNU Library General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *	
 *	Mark's Code Fractal CFSec is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU Library General Public License
 *	along with Mark's Code Fractal CFSec.  If not, see <https://www.gnu.org/licenses/>.
 *	
 *	If you wish to modify and use this code without publishing your changes in order to
 *	tie it to proprietary code, please contact Mark Stephen Sobkow
 *	for a commercial license at mark.sobkow@gmail.com
 *	
 */

package io.github.msobkow.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import io.github.msobkow.v3_1.cflib.*;
import io.github.msobkow.v3_1.cflib.dbutil.*;

import io.github.msobkow.v3_1.cfsec.cfsec.*;
import io.github.msobkow.v3_1.cfsec.cfsec.buff.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamServiceTable in-memory RAM DbIO implementation
 *	for Service.
 */
public class CFSecRamServiceTable
	implements ICFSecServiceTable
{
	private ICFSecSchema schema;
	private Map< CFLibDbKeyHash256,
				CFSecBuffService > dictByPKey
		= new HashMap< CFLibDbKeyHash256,
				CFSecBuffService >();
	private Map< CFSecBuffServiceByClusterIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffService >> dictByClusterIdx
		= new HashMap< CFSecBuffServiceByClusterIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffService >>();
	private Map< CFSecBuffServiceByHostIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffService >> dictByHostIdx
		= new HashMap< CFSecBuffServiceByHostIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffService >>();
	private Map< CFSecBuffServiceByTypeIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffService >> dictByTypeIdx
		= new HashMap< CFSecBuffServiceByTypeIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffService >>();
	private Map< CFSecBuffServiceByUTypeIdxKey,
			CFSecBuffService > dictByUTypeIdx
		= new HashMap< CFSecBuffServiceByUTypeIdxKey,
			CFSecBuffService >();
	private Map< CFSecBuffServiceByUHostPortIdxKey,
			CFSecBuffService > dictByUHostPortIdx
		= new HashMap< CFSecBuffServiceByUHostPortIdxKey,
			CFSecBuffService >();

	public CFSecRamServiceTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffService ensureRec(ICFSecService rec) {
		if (rec == null) {
			return( null );
		}
		else {
			int classCode = rec.getClassCode();
			if (classCode == ICFSecService.CLASS_CODE) {
				return( ((CFSecBuffServiceDefaultFactory)(schema.getFactoryService())).ensureRec(rec) );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), "ensureRec", "rec", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	public ICFSecService createService( ICFSecAuthorization Authorization,
		ICFSecService iBuff )
	{
		final String S_ProcName = "createService";
		
		CFSecBuffService Buff = ensureRec(iBuff);
		CFLibDbKeyHash256 pkey;
		pkey = schema.nextServiceIdGen();
		Buff.setRequiredServiceId( pkey );
		CFSecBuffServiceByClusterIdxKey keyClusterIdx = (CFSecBuffServiceByClusterIdxKey)schema.getFactoryService().newByClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecBuffServiceByHostIdxKey keyHostIdx = (CFSecBuffServiceByHostIdxKey)schema.getFactoryService().newByHostIdxKey();
		keyHostIdx.setRequiredHostNodeId( Buff.getRequiredHostNodeId() );

		CFSecBuffServiceByTypeIdxKey keyTypeIdx = (CFSecBuffServiceByTypeIdxKey)schema.getFactoryService().newByTypeIdxKey();
		keyTypeIdx.setRequiredServiceTypeId( Buff.getRequiredServiceTypeId() );

		CFSecBuffServiceByUTypeIdxKey keyUTypeIdx = (CFSecBuffServiceByUTypeIdxKey)schema.getFactoryService().newByUTypeIdxKey();
		keyUTypeIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyUTypeIdx.setRequiredHostNodeId( Buff.getRequiredHostNodeId() );
		keyUTypeIdx.setRequiredServiceTypeId( Buff.getRequiredServiceTypeId() );

		CFSecBuffServiceByUHostPortIdxKey keyUHostPortIdx = (CFSecBuffServiceByUHostPortIdxKey)schema.getFactoryService().newByUHostPortIdxKey();
		keyUHostPortIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyUHostPortIdx.setRequiredHostNodeId( Buff.getRequiredHostNodeId() );
		keyUHostPortIdx.setRequiredHostPort( Buff.getRequiredHostPort() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUTypeIdx.containsKey( keyUTypeIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"ServiceUTypeIdx",
				"ServiceUTypeIdx",
				keyUTypeIdx );
		}

		if( dictByUHostPortIdx.containsKey( keyUHostPortIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"ServiceUHostPort",
				"ServiceUHostPort",
				keyUHostPortIdx );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableCluster().readDerivedByIdIdx( Authorization,
						Buff.getRequiredClusterId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Owner",
						"ServiceCluster",
						"Cluster",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffService > subdictClusterIdx;
		if( dictByClusterIdx.containsKey( keyClusterIdx ) ) {
			subdictClusterIdx = dictByClusterIdx.get( keyClusterIdx );
		}
		else {
			subdictClusterIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffService >();
			dictByClusterIdx.put( keyClusterIdx, subdictClusterIdx );
		}
		subdictClusterIdx.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffService > subdictHostIdx;
		if( dictByHostIdx.containsKey( keyHostIdx ) ) {
			subdictHostIdx = dictByHostIdx.get( keyHostIdx );
		}
		else {
			subdictHostIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffService >();
			dictByHostIdx.put( keyHostIdx, subdictHostIdx );
		}
		subdictHostIdx.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffService > subdictTypeIdx;
		if( dictByTypeIdx.containsKey( keyTypeIdx ) ) {
			subdictTypeIdx = dictByTypeIdx.get( keyTypeIdx );
		}
		else {
			subdictTypeIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffService >();
			dictByTypeIdx.put( keyTypeIdx, subdictTypeIdx );
		}
		subdictTypeIdx.put( pkey, Buff );

		dictByUTypeIdx.put( keyUTypeIdx, Buff );

		dictByUHostPortIdx.put( keyUHostPortIdx, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecService.CLASS_CODE) {
				CFSecBuffService retbuff = ((CFSecBuffService)(schema.getFactoryService().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	public ICFSecService readDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamService.readDerived";
		ICFSecService buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecService lockDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamService.readDerived";
		ICFSecService buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecService[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamService.readAllDerived";
		ICFSecService[] retList = new ICFSecService[ dictByPKey.values().size() ];
		Iterator< CFSecBuffService > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public ICFSecService[] readDerivedByClusterIdx( ICFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFSecRamService.readDerivedByClusterIdx";
		CFSecBuffServiceByClusterIdxKey key = (CFSecBuffServiceByClusterIdxKey)schema.getFactoryService().newByClusterIdxKey();
		key.setRequiredClusterId( ClusterId );

		ICFSecService[] recArray;
		if( dictByClusterIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffService > subdictClusterIdx
				= dictByClusterIdx.get( key );
			recArray = new ICFSecService[ subdictClusterIdx.size() ];
			Iterator< CFSecBuffService > iter = subdictClusterIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffService > subdictClusterIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffService >();
			dictByClusterIdx.put( key, subdictClusterIdx );
			recArray = new ICFSecService[0];
		}
		return( recArray );
	}

	public ICFSecService[] readDerivedByHostIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 HostNodeId )
	{
		final String S_ProcName = "CFSecRamService.readDerivedByHostIdx";
		CFSecBuffServiceByHostIdxKey key = (CFSecBuffServiceByHostIdxKey)schema.getFactoryService().newByHostIdxKey();
		key.setRequiredHostNodeId( HostNodeId );

		ICFSecService[] recArray;
		if( dictByHostIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffService > subdictHostIdx
				= dictByHostIdx.get( key );
			recArray = new ICFSecService[ subdictHostIdx.size() ];
			Iterator< CFSecBuffService > iter = subdictHostIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffService > subdictHostIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffService >();
			dictByHostIdx.put( key, subdictHostIdx );
			recArray = new ICFSecService[0];
		}
		return( recArray );
	}

	public ICFSecService[] readDerivedByTypeIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 ServiceTypeId )
	{
		final String S_ProcName = "CFSecRamService.readDerivedByTypeIdx";
		CFSecBuffServiceByTypeIdxKey key = (CFSecBuffServiceByTypeIdxKey)schema.getFactoryService().newByTypeIdxKey();
		key.setRequiredServiceTypeId( ServiceTypeId );

		ICFSecService[] recArray;
		if( dictByTypeIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffService > subdictTypeIdx
				= dictByTypeIdx.get( key );
			recArray = new ICFSecService[ subdictTypeIdx.size() ];
			Iterator< CFSecBuffService > iter = subdictTypeIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffService > subdictTypeIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffService >();
			dictByTypeIdx.put( key, subdictTypeIdx );
			recArray = new ICFSecService[0];
		}
		return( recArray );
	}

	public ICFSecService readDerivedByUTypeIdx( ICFSecAuthorization Authorization,
		long ClusterId,
		CFLibDbKeyHash256 HostNodeId,
		CFLibDbKeyHash256 ServiceTypeId )
	{
		final String S_ProcName = "CFSecRamService.readDerivedByUTypeIdx";
		CFSecBuffServiceByUTypeIdxKey key = (CFSecBuffServiceByUTypeIdxKey)schema.getFactoryService().newByUTypeIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredHostNodeId( HostNodeId );
		key.setRequiredServiceTypeId( ServiceTypeId );

		ICFSecService buff;
		if( dictByUTypeIdx.containsKey( key ) ) {
			buff = dictByUTypeIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecService readDerivedByUHostPortIdx( ICFSecAuthorization Authorization,
		long ClusterId,
		CFLibDbKeyHash256 HostNodeId,
		short HostPort )
	{
		final String S_ProcName = "CFSecRamService.readDerivedByUHostPortIdx";
		CFSecBuffServiceByUHostPortIdxKey key = (CFSecBuffServiceByUHostPortIdxKey)schema.getFactoryService().newByUHostPortIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredHostNodeId( HostNodeId );
		key.setRequiredHostPort( HostPort );

		ICFSecService buff;
		if( dictByUHostPortIdx.containsKey( key ) ) {
			buff = dictByUHostPortIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecService readDerivedByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 ServiceId )
	{
		final String S_ProcName = "CFSecRamService.readDerivedByIdIdx() ";
		ICFSecService buff;
		if( dictByPKey.containsKey( ServiceId ) ) {
			buff = dictByPKey.get( ServiceId );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecService readBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamService.readBuff";
		ICFSecService buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecService.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecService lockBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "lockBuff";
		ICFSecService buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecService.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecService[] readAllBuff( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamService.readAllBuff";
		ICFSecService buff;
		ArrayList<ICFSecService> filteredList = new ArrayList<ICFSecService>();
		ICFSecService[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecService.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecService[0] ) );
	}

	/**
	 *	Read a page of all the specific Service buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific Service instances in the database accessible for the Authorization.
	 */
	public ICFSecService[] pageAllBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorServiceId )
	{
		final String S_ProcName = "pageAllBuff";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public ICFSecService readBuffByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 ServiceId )
	{
		final String S_ProcName = "CFSecRamService.readBuffByIdIdx() ";
		ICFSecService buff = readDerivedByIdIdx( Authorization,
			ServiceId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecService.CLASS_CODE ) ) {
			return( (ICFSecService)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecService[] readBuffByClusterIdx( ICFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFSecRamService.readBuffByClusterIdx() ";
		ICFSecService buff;
		ArrayList<ICFSecService> filteredList = new ArrayList<ICFSecService>();
		ICFSecService[] buffList = readDerivedByClusterIdx( Authorization,
			ClusterId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecService.CLASS_CODE ) ) {
				filteredList.add( (ICFSecService)buff );
			}
		}
		return( filteredList.toArray( new ICFSecService[0] ) );
	}

	public ICFSecService[] readBuffByHostIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 HostNodeId )
	{
		final String S_ProcName = "CFSecRamService.readBuffByHostIdx() ";
		ICFSecService buff;
		ArrayList<ICFSecService> filteredList = new ArrayList<ICFSecService>();
		ICFSecService[] buffList = readDerivedByHostIdx( Authorization,
			HostNodeId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecService.CLASS_CODE ) ) {
				filteredList.add( (ICFSecService)buff );
			}
		}
		return( filteredList.toArray( new ICFSecService[0] ) );
	}

	public ICFSecService[] readBuffByTypeIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 ServiceTypeId )
	{
		final String S_ProcName = "CFSecRamService.readBuffByTypeIdx() ";
		ICFSecService buff;
		ArrayList<ICFSecService> filteredList = new ArrayList<ICFSecService>();
		ICFSecService[] buffList = readDerivedByTypeIdx( Authorization,
			ServiceTypeId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecService.CLASS_CODE ) ) {
				filteredList.add( (ICFSecService)buff );
			}
		}
		return( filteredList.toArray( new ICFSecService[0] ) );
	}

	public ICFSecService readBuffByUTypeIdx( ICFSecAuthorization Authorization,
		long ClusterId,
		CFLibDbKeyHash256 HostNodeId,
		CFLibDbKeyHash256 ServiceTypeId )
	{
		final String S_ProcName = "CFSecRamService.readBuffByUTypeIdx() ";
		ICFSecService buff = readDerivedByUTypeIdx( Authorization,
			ClusterId,
			HostNodeId,
			ServiceTypeId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecService.CLASS_CODE ) ) {
			return( (ICFSecService)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecService readBuffByUHostPortIdx( ICFSecAuthorization Authorization,
		long ClusterId,
		CFLibDbKeyHash256 HostNodeId,
		short HostPort )
	{
		final String S_ProcName = "CFSecRamService.readBuffByUHostPortIdx() ";
		ICFSecService buff = readDerivedByUHostPortIdx( Authorization,
			ClusterId,
			HostNodeId,
			HostPort );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecService.CLASS_CODE ) ) {
			return( (ICFSecService)buff );
		}
		else {
			return( null );
		}
	}

	/**
	 *	Read a page array of the specific Service buffer instances identified by the duplicate key ClusterIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	ClusterId	The Service key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public ICFSecService[] pageBuffByClusterIdx( ICFSecAuthorization Authorization,
		long ClusterId,
		CFLibDbKeyHash256 priorServiceId )
	{
		final String S_ProcName = "pageBuffByClusterIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific Service buffer instances identified by the duplicate key HostIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	HostNodeId	The Service key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public ICFSecService[] pageBuffByHostIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 HostNodeId,
		CFLibDbKeyHash256 priorServiceId )
	{
		final String S_ProcName = "pageBuffByHostIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific Service buffer instances identified by the duplicate key TypeIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	ServiceTypeId	The Service key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public ICFSecService[] pageBuffByTypeIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 ServiceTypeId,
		CFLibDbKeyHash256 priorServiceId )
	{
		final String S_ProcName = "pageBuffByTypeIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public ICFSecService updateService( ICFSecAuthorization Authorization,
		ICFSecService iBuff )
	{
		CFSecBuffService Buff = ensureRec(iBuff);
		CFLibDbKeyHash256 pkey = Buff.getPKey();
		CFSecBuffService existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateService",
				"Existing record not found",
				"Existing record not found",
				"Service",
				"Service",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateService",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffServiceByClusterIdxKey existingKeyClusterIdx = (CFSecBuffServiceByClusterIdxKey)schema.getFactoryService().newByClusterIdxKey();
		existingKeyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecBuffServiceByClusterIdxKey newKeyClusterIdx = (CFSecBuffServiceByClusterIdxKey)schema.getFactoryService().newByClusterIdxKey();
		newKeyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecBuffServiceByHostIdxKey existingKeyHostIdx = (CFSecBuffServiceByHostIdxKey)schema.getFactoryService().newByHostIdxKey();
		existingKeyHostIdx.setRequiredHostNodeId( existing.getRequiredHostNodeId() );

		CFSecBuffServiceByHostIdxKey newKeyHostIdx = (CFSecBuffServiceByHostIdxKey)schema.getFactoryService().newByHostIdxKey();
		newKeyHostIdx.setRequiredHostNodeId( Buff.getRequiredHostNodeId() );

		CFSecBuffServiceByTypeIdxKey existingKeyTypeIdx = (CFSecBuffServiceByTypeIdxKey)schema.getFactoryService().newByTypeIdxKey();
		existingKeyTypeIdx.setRequiredServiceTypeId( existing.getRequiredServiceTypeId() );

		CFSecBuffServiceByTypeIdxKey newKeyTypeIdx = (CFSecBuffServiceByTypeIdxKey)schema.getFactoryService().newByTypeIdxKey();
		newKeyTypeIdx.setRequiredServiceTypeId( Buff.getRequiredServiceTypeId() );

		CFSecBuffServiceByUTypeIdxKey existingKeyUTypeIdx = (CFSecBuffServiceByUTypeIdxKey)schema.getFactoryService().newByUTypeIdxKey();
		existingKeyUTypeIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyUTypeIdx.setRequiredHostNodeId( existing.getRequiredHostNodeId() );
		existingKeyUTypeIdx.setRequiredServiceTypeId( existing.getRequiredServiceTypeId() );

		CFSecBuffServiceByUTypeIdxKey newKeyUTypeIdx = (CFSecBuffServiceByUTypeIdxKey)schema.getFactoryService().newByUTypeIdxKey();
		newKeyUTypeIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyUTypeIdx.setRequiredHostNodeId( Buff.getRequiredHostNodeId() );
		newKeyUTypeIdx.setRequiredServiceTypeId( Buff.getRequiredServiceTypeId() );

		CFSecBuffServiceByUHostPortIdxKey existingKeyUHostPortIdx = (CFSecBuffServiceByUHostPortIdxKey)schema.getFactoryService().newByUHostPortIdxKey();
		existingKeyUHostPortIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyUHostPortIdx.setRequiredHostNodeId( existing.getRequiredHostNodeId() );
		existingKeyUHostPortIdx.setRequiredHostPort( existing.getRequiredHostPort() );

		CFSecBuffServiceByUHostPortIdxKey newKeyUHostPortIdx = (CFSecBuffServiceByUHostPortIdxKey)schema.getFactoryService().newByUHostPortIdxKey();
		newKeyUHostPortIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyUHostPortIdx.setRequiredHostNodeId( Buff.getRequiredHostNodeId() );
		newKeyUHostPortIdx.setRequiredHostPort( Buff.getRequiredHostPort() );

		// Check unique indexes

		if( ! existingKeyUTypeIdx.equals( newKeyUTypeIdx ) ) {
			if( dictByUTypeIdx.containsKey( newKeyUTypeIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateService",
					"ServiceUTypeIdx",
					"ServiceUTypeIdx",
					newKeyUTypeIdx );
			}
		}

		if( ! existingKeyUHostPortIdx.equals( newKeyUHostPortIdx ) ) {
			if( dictByUHostPortIdx.containsKey( newKeyUHostPortIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateService",
					"ServiceUHostPort",
					"ServiceUHostPort",
					newKeyUHostPortIdx );
			}
		}

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableCluster().readDerivedByIdIdx( Authorization,
						Buff.getRequiredClusterId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateService",
						"Owner",
						"ServiceCluster",
						"Cluster",
						null );
				}
			}
		}

		// Update is valid

		Map< CFLibDbKeyHash256, CFSecBuffService > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictByClusterIdx.get( existingKeyClusterIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByClusterIdx.containsKey( newKeyClusterIdx ) ) {
			subdict = dictByClusterIdx.get( newKeyClusterIdx );
		}
		else {
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffService >();
			dictByClusterIdx.put( newKeyClusterIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByHostIdx.get( existingKeyHostIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByHostIdx.containsKey( newKeyHostIdx ) ) {
			subdict = dictByHostIdx.get( newKeyHostIdx );
		}
		else {
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffService >();
			dictByHostIdx.put( newKeyHostIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByTypeIdx.get( existingKeyTypeIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByTypeIdx.containsKey( newKeyTypeIdx ) ) {
			subdict = dictByTypeIdx.get( newKeyTypeIdx );
		}
		else {
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffService >();
			dictByTypeIdx.put( newKeyTypeIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByUTypeIdx.remove( existingKeyUTypeIdx );
		dictByUTypeIdx.put( newKeyUTypeIdx, Buff );

		dictByUHostPortIdx.remove( existingKeyUHostPortIdx );
		dictByUHostPortIdx.put( newKeyUHostPortIdx, Buff );

		return(Buff);
	}

	public void deleteService( ICFSecAuthorization Authorization,
		ICFSecService iBuff )
	{
		final String S_ProcName = "CFSecRamServiceTable.deleteService() ";
		CFSecBuffService Buff = ensureRec(iBuff);
		int classCode;
		CFLibDbKeyHash256 pkey = (CFLibDbKeyHash256)(Buff.getPKey());
		CFSecBuffService existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteService",
				pkey );
		}
		CFSecBuffServiceByClusterIdxKey keyClusterIdx = (CFSecBuffServiceByClusterIdxKey)schema.getFactoryService().newByClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecBuffServiceByHostIdxKey keyHostIdx = (CFSecBuffServiceByHostIdxKey)schema.getFactoryService().newByHostIdxKey();
		keyHostIdx.setRequiredHostNodeId( existing.getRequiredHostNodeId() );

		CFSecBuffServiceByTypeIdxKey keyTypeIdx = (CFSecBuffServiceByTypeIdxKey)schema.getFactoryService().newByTypeIdxKey();
		keyTypeIdx.setRequiredServiceTypeId( existing.getRequiredServiceTypeId() );

		CFSecBuffServiceByUTypeIdxKey keyUTypeIdx = (CFSecBuffServiceByUTypeIdxKey)schema.getFactoryService().newByUTypeIdxKey();
		keyUTypeIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyUTypeIdx.setRequiredHostNodeId( existing.getRequiredHostNodeId() );
		keyUTypeIdx.setRequiredServiceTypeId( existing.getRequiredServiceTypeId() );

		CFSecBuffServiceByUHostPortIdxKey keyUHostPortIdx = (CFSecBuffServiceByUHostPortIdxKey)schema.getFactoryService().newByUHostPortIdxKey();
		keyUHostPortIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyUHostPortIdx.setRequiredHostNodeId( existing.getRequiredHostNodeId() );
		keyUHostPortIdx.setRequiredHostPort( existing.getRequiredHostPort() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFLibDbKeyHash256, CFSecBuffService > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByClusterIdx.get( keyClusterIdx );
		subdict.remove( pkey );

		subdict = dictByHostIdx.get( keyHostIdx );
		subdict.remove( pkey );

		subdict = dictByTypeIdx.get( keyTypeIdx );
		subdict.remove( pkey );

		dictByUTypeIdx.remove( keyUTypeIdx );

		dictByUHostPortIdx.remove( keyUHostPortIdx );

	}
	public void deleteServiceByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		ICFSecService cur;
		LinkedList<ICFSecService> matchSet = new LinkedList<ICFSecService>();
		Iterator<ICFSecService> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecService> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableService().readDerivedByIdIdx( Authorization,
				cur.getRequiredServiceId() );
			deleteService( Authorization, cur );
		}
	}

	public void deleteServiceByClusterIdx( ICFSecAuthorization Authorization,
		long argClusterId )
	{
		CFSecBuffServiceByClusterIdxKey key = (CFSecBuffServiceByClusterIdxKey)schema.getFactoryService().newByClusterIdxKey();
		key.setRequiredClusterId( argClusterId );
		deleteServiceByClusterIdx( Authorization, key );
	}

	public void deleteServiceByClusterIdx( ICFSecAuthorization Authorization,
		ICFSecServiceByClusterIdxKey argKey )
	{
		ICFSecService cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecService> matchSet = new LinkedList<ICFSecService>();
		Iterator<ICFSecService> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecService> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableService().readDerivedByIdIdx( Authorization,
				cur.getRequiredServiceId() );
			deleteService( Authorization, cur );
		}
	}

	public void deleteServiceByHostIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argHostNodeId )
	{
		CFSecBuffServiceByHostIdxKey key = (CFSecBuffServiceByHostIdxKey)schema.getFactoryService().newByHostIdxKey();
		key.setRequiredHostNodeId( argHostNodeId );
		deleteServiceByHostIdx( Authorization, key );
	}

	public void deleteServiceByHostIdx( ICFSecAuthorization Authorization,
		ICFSecServiceByHostIdxKey argKey )
	{
		ICFSecService cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecService> matchSet = new LinkedList<ICFSecService>();
		Iterator<ICFSecService> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecService> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableService().readDerivedByIdIdx( Authorization,
				cur.getRequiredServiceId() );
			deleteService( Authorization, cur );
		}
	}

	public void deleteServiceByTypeIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argServiceTypeId )
	{
		CFSecBuffServiceByTypeIdxKey key = (CFSecBuffServiceByTypeIdxKey)schema.getFactoryService().newByTypeIdxKey();
		key.setRequiredServiceTypeId( argServiceTypeId );
		deleteServiceByTypeIdx( Authorization, key );
	}

	public void deleteServiceByTypeIdx( ICFSecAuthorization Authorization,
		ICFSecServiceByTypeIdxKey argKey )
	{
		ICFSecService cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecService> matchSet = new LinkedList<ICFSecService>();
		Iterator<ICFSecService> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecService> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableService().readDerivedByIdIdx( Authorization,
				cur.getRequiredServiceId() );
			deleteService( Authorization, cur );
		}
	}

	public void deleteServiceByUTypeIdx( ICFSecAuthorization Authorization,
		long argClusterId,
		CFLibDbKeyHash256 argHostNodeId,
		CFLibDbKeyHash256 argServiceTypeId )
	{
		CFSecBuffServiceByUTypeIdxKey key = (CFSecBuffServiceByUTypeIdxKey)schema.getFactoryService().newByUTypeIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredHostNodeId( argHostNodeId );
		key.setRequiredServiceTypeId( argServiceTypeId );
		deleteServiceByUTypeIdx( Authorization, key );
	}

	public void deleteServiceByUTypeIdx( ICFSecAuthorization Authorization,
		ICFSecServiceByUTypeIdxKey argKey )
	{
		ICFSecService cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecService> matchSet = new LinkedList<ICFSecService>();
		Iterator<ICFSecService> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecService> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableService().readDerivedByIdIdx( Authorization,
				cur.getRequiredServiceId() );
			deleteService( Authorization, cur );
		}
	}

	public void deleteServiceByUHostPortIdx( ICFSecAuthorization Authorization,
		long argClusterId,
		CFLibDbKeyHash256 argHostNodeId,
		short argHostPort )
	{
		CFSecBuffServiceByUHostPortIdxKey key = (CFSecBuffServiceByUHostPortIdxKey)schema.getFactoryService().newByUHostPortIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredHostNodeId( argHostNodeId );
		key.setRequiredHostPort( argHostPort );
		deleteServiceByUHostPortIdx( Authorization, key );
	}

	public void deleteServiceByUHostPortIdx( ICFSecAuthorization Authorization,
		ICFSecServiceByUHostPortIdxKey argKey )
	{
		ICFSecService cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecService> matchSet = new LinkedList<ICFSecService>();
		Iterator<ICFSecService> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecService> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableService().readDerivedByIdIdx( Authorization,
				cur.getRequiredServiceId() );
			deleteService( Authorization, cur );
		}
	}
}
